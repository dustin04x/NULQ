package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
)

type Baseline struct {
	Name        string    `json:"name"`
	ReportID    string    `json:"report_id"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description,omitempty"`
}

func (s *Store) baselinePath(name string) (string, error) {
	if err := safeID(name); err != nil {
		return "", err
	}
	return filepath.Join(s.baselinesDir(), name+".json"), nil
}

func (s *Store) CreateBaseline(name, reportID, desc string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createBaselineLocked(name, reportID, desc)
}

func (s *Store) createBaselineLocked(name, reportID, desc string) error {
	if err := s.ensureDirs(); err != nil {
		return err
	}
	// Validate the referenced report exists. Existence is sufficient here;
	// LoadReport performs full validation when the report is read.
	rp, err := s.reportPath(reportID)
	if err != nil {
		return fmt.Errorf("report not found: %s", reportID)
	}
	info, err := os.Lstat(rp)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("report not found: %s", reportID)
		}
		return fmt.Errorf("report not found: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing symlink")
	}
	p, err := s.baselinePath(name)
	if err != nil {
		return err
	}
	// Reject symlinks and existing baselines before writing.
	info, err = os.Lstat(p)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing symlink")
		}
		return fmt.Errorf("baseline already exists: %s", name)
	}
	if !os.IsNotExist(err) {
		return err
	}
	b := Baseline{Name: name, ReportID: reportID, CreatedAt: time.Now().UTC(), Description: desc}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
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
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	info, err = os.Lstat(p)
	if err == nil {
		os.Remove(tmp)
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing symlink")
		}
		return fmt.Errorf("baseline already exists: %s", name)
	}
	if !os.IsNotExist(err) {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return s.syncDir(s.baselinesDir())
}

func (s *Store) LoadBaseline(name string) (Baseline, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadBaselineLocked(name)
}

func (s *Store) loadBaselineLocked(name string) (Baseline, error) {
	p, err := s.baselinePath(name)
	if err != nil {
		return Baseline{}, err
	}
	info, err := os.Lstat(p)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return Baseline{}, errors.New("refusing symlink")
		}
	} else if !os.IsNotExist(err) {
		return Baseline{}, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return Baseline{}, err
		}
		return Baseline{}, errors.New("refusing symlink")
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return Baseline{}, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return Baseline{}, errors.New("refusing symlink")
	}
	if st.Size() > maxReportSize {
		f.Close()
		return Baseline{}, errors.New("baseline too large")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return Baseline{}, err
	}
	if err := f.Close(); err != nil {
		return Baseline{}, err
	}
	if len(data) > maxReportSize {
		return Baseline{}, errors.New("baseline too large")
	}
	if err := assertJSONDepth(data); err != nil {
		return Baseline{}, err
	}
	var b Baseline
	// json.Unmarshal rejects trailing data after the top-level value.
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, err
	}
	return b, nil
}

func (s *Store) ListBaselines() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listBaselinesLocked()
}

func (s *Store) listBaselinesLocked() ([]string, error) {
	if err := s.ensureDirs(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.baselinesDir())
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !hasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, trimSuffix(e.Name(), ".json"))
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return names, nil
}

func (s *Store) DeleteBaseline(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteBaselineLocked(name)
}

func (s *Store) deleteBaselineLocked(name string) error {
	p, err := s.baselinePath(name)
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
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(p)
}

// helper to avoid import name clash
func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }
func trimSuffix(s, suf string) string {
	if hasSuffix(s, suf) {
		return s[:len(s)-len(suf)]
	}
	return s
}

var _ = models.Report{}
