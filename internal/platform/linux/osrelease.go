package linux

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// OSRelease holds parsed /etc/os-release fields.
type OSRelease struct {
	ID         string
	IDLike     []string
	Name       string
	VersionID  string
	PrettyName string
	Raw        map[string]string
}

// ParseOSRelease parses os-release content. Returns empty OSRelease on missing file.
// ParseOSReleaseBytes parses os-release content from bytes.
func ParseOSReleaseBytes(data []byte) (OSRelease, error) {
	if len(data) > 1024*1024 {
		return OSRelease{}, fmt.Errorf("os-release too large: %d bytes", len(data))
	}
	r := OSRelease{Raw: map[string]string{}}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = unquote(val)
		if key == "" {
			continue
		}
		r.Raw[key] = val
		switch key {
		case "ID":
			r.ID = val
		case "ID_LIKE":
			r.IDLike = strings.Fields(val)
		case "NAME":
			r.Name = val
		case "VERSION_ID":
			r.VersionID = val
		case "PRETTY_NAME":
			r.PrettyName = val
		}
	}
	if err := sc.Err(); err != nil {
		return r, err
	}
	return r, nil
}

func ParseOSRelease(path string) (OSRelease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return OSRelease{}, err
	}
	return ParseOSReleaseBytes(data)
}

var _ = fmt.Sprintf

func unquote(v string) string {
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		v = v[1 : len(v)-1]
	}
	v = strings.ReplaceAll(v, "\\\"", "\"")
	v = strings.ReplaceAll(v, "\\\\", "\\")
	v = strings.ReplaceAll(v, "\\$", "$")
	v = strings.ReplaceAll(v, "\\`", "`")
	return v
}

func (r OSRelease) DistributionFamily() string {
	id := strings.ToLower(r.ID)
	switch id {
	case "debian", "ubuntu", "linuxmint", "pop":
		return "debian"
	case "alpine":
		return "alpine"
	case "arch", "manjaro", "endeavouros":
		return "arch"
	case "fedora", "rhel", "centos", "rocky", "almalinux":
		return "fedora"
	default:
		for _, l := range r.IDLike {
			l = strings.ToLower(l)
			switch l {
			case "debian", "ubuntu":
				return "debian"
			case "alpine":
				return "alpine"
			case "arch":
				return "arch"
			case "fedora", "rhel":
				return "fedora"
			}
		}
		if id != "" {
			return id
		}
		return "unknown"
	}
}
