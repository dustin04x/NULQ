package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/dustin04x/nulq/internal/core/models"
)

const (
	// maxReportSize caps the size of a persisted report so a hostile or
	// corrupted file cannot exhaust memory while decoding.
	maxReportSize = 64 * 1024 * 1024
	// maxJSONDepth limits the nesting depth of persisted JSON so a deeply
	// nested document cannot exhaust the decoder stack.
	maxJSONDepth = 1000
	// maxIDLen bounds report and baseline identifier length.
	maxIDLen = 128
)

// DefaultDir returns the default storage directory.
func DefaultDir() string {
	if v := os.Getenv("NULQ_DATA_DIR"); v != "" {
		return v
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "nulq")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".nulq")
	}
	return filepath.Join(home, ".local", "share", "nulq")
}

func safeID(id string) error {
	if id == "" {
		return errors.New("empty id")
	}
	if len(id) > maxIDLen {
		return fmt.Errorf("id too long: %d bytes", len(id))
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return errors.New("invalid id")
	}
	for _, r := range id {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("invalid character in id: %q", r)
		}
	}
	return nil
}

type Store struct {
	Dir string
	mu  sync.Mutex
}

func New(dir string) *Store {
	if dir == "" {
		dir = DefaultDir()
	}
	return &Store{Dir: dir}
}

func (s *Store) reportsDir() string   { return filepath.Join(s.Dir, "reports") }
func (s *Store) baselinesDir() string { return filepath.Join(s.Dir, "baselines") }

func (s *Store) ensureDirs() error {
	for _, d := range []string{s.reportsDir(), s.baselinesDir()} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Store) reportPath(id string) (string, error) {
	if err := safeID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.reportsDir(), id+".json"), nil
}

func (s *Store) SaveReport(r models.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveReportLocked(r)
}

func (s *Store) saveReportLocked(r models.Report) error {
	if err := s.ensureDirs(); err != nil {
		return err
	}
	p, err := s.reportPath(r.Scan.ReportID)
	if err != nil {
		return err
	}
	// Reject symlinks and existing files before writing anything.
	info, err := os.Lstat(p)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing symlink")
		}
		return fmt.Errorf("report already exists: %s", r.Scan.ReportID)
	}
	if !os.IsNotExist(err) {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	// Remove a stale temp file left by a crashed previous write, then create
	// the temp file exclusively and exclusively (no symlink following).
	if _, err := os.Lstat(tmp); err == nil {
		if err := os.Remove(tmp); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// Make the temp file durable before it becomes visible via rename.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Re-check right before rename: an external process may have planted a
	// symlink at p since the first Lstat.
	info, err = os.Lstat(p)
	if err == nil {
		os.Remove(tmp)
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing symlink")
		}
		return fmt.Errorf("report already exists: %s", r.Scan.ReportID)
	}
	if !os.IsNotExist(err) {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	// Persist the directory metadata so the rename is durable.
	if err := s.syncDir(s.reportsDir()); err != nil {
		return err
	}
	return nil
}

func (s *Store) LoadReport(id string) (models.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadReportLocked(id)
}

func (s *Store) loadReportLocked(id string) (models.Report, error) {
	p, err := s.reportPath(id)
	if err != nil {
		return models.Report{}, err
	}
	// Reject symlinks up front; the O_NOFOLLOW open below defends against a
	// swap between this Lstat and the open.
	info, err := os.Lstat(p)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return models.Report{}, errors.New("refusing symlink")
		}
	} else if !os.IsNotExist(err) {
		return models.Report{}, err
	}
	// O_NOFOLLOW fails (ELOOP) if p is a symlink, so we never read through
	// one even if it is planted after the Lstat above.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return models.Report{}, err
		}
		return models.Report{}, errors.New("refusing symlink")
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return models.Report{}, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return models.Report{}, errors.New("refusing symlink")
	}
	if st.Size() > maxReportSize {
		f.Close()
		return models.Report{}, errors.New("report too large")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return models.Report{}, err
	}
	if err := f.Close(); err != nil {
		return models.Report{}, err
	}
	if len(data) > maxReportSize {
		return models.Report{}, errors.New("report too large")
	}
	if err := assertJSONDepth(data); err != nil {
		return models.Report{}, err
	}
	var r models.Report
	// json.Unmarshal rejects trailing data after the top-level value, so a
	// persisted report must be a single JSON document.
	if err := json.Unmarshal(data, &r); err != nil {
		return models.Report{}, err
	}
	if r.SchemaVersion != models.SchemaVersion {
		return models.Report{}, fmt.Errorf("unsupported schema version %q", r.SchemaVersion)
	}
	// The persisted identifier must match the name it was loaded under.
	if r.Scan.ReportID != id {
		return models.Report{}, fmt.Errorf("report id mismatch: file %q, content %q", id, r.Scan.ReportID)
	}
	return r, nil
}

// assertJSONDepth rejects JSON whose nesting exceeds maxJSONDepth, so a
// hostile document cannot exhaust the decoder stack.
func assertJSONDepth(data []byte) error {
	depth := 0
	max := 0
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		b := data[i]
		switch {
		case inString:
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
		case b == '"':
			inString = true
		case b == '{', b == '[':
			depth++
			if depth > max {
				max = depth
			}
			if max > maxJSONDepth {
				return errors.New("JSON nesting depth exceeds limit")
			}
		case b == '}', b == ']':
			depth--
		}
	}
	if inString || depth != 0 {
		return errors.New("malformed JSON: unterminated string or unbalanced braces")
	}
	return nil
}

func (s *Store) ListReports() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listReportsLocked()
}

func (s *Store) listReportsLocked() ([]string, error) {
	if err := s.ensureDirs(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.reportsDir())
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		ids = append(ids, strings.TrimSuffix(name, ".json"))
	}
	// simple sort
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	return ids, nil
}

func (s *Store) DeleteReport(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteReportLocked(id)
}

func (s *Store) deleteReportLocked(id string) error {
	p, err := s.reportPath(id)
	if err != nil {
		return err
	}
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing symlink")
	}
	// Open with O_NOFOLLOW to confirm the name is not a symlink, then remove
	// the directory entry itself. We never unlink through a symlink.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(p)
}
