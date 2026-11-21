// Package version exposes build metadata for NULQ.
//
// Version, Commit and BuildDate are overridden at build time with
// -ldflags "-X ...". Defaults are intentionally honest about being
// development builds rather than fabricated release values.
package version

import "runtime"

var (
	// Version is the semantic version of this build.
	Version = "0.1.0-dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// BuildDate is the RFC 3339 UTC timestamp of the build.
	BuildDate = "unknown"
)

// Info is a serialisable description of the binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Current returns the build metadata for the running binary.
func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}
