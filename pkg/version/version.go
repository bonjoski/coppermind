// Package version defines the single source of truth for the Coppermind project version,
// build commit hash, and build timestamp.
package version

import "fmt"

var (
	// Version is the current semantic version of Coppermind.
	Version = "0.9.0"

	// Commit is the git commit SHA injected at build time via -ldflags.
	Commit = "dev"

	// BuildTime is the ISO-8601/RFC-3339 build timestamp injected at build time via -ldflags.
	BuildTime = ""
)

// String returns formatted version details.
func String() string {
	if Commit != "dev" && Commit != "" {
		if BuildTime != "" {
			return fmt.Sprintf("%s (%s, %s)", Version, Commit, BuildTime)
		}
		return fmt.Sprintf("%s (%s)", Version, Commit)
	}
	return Version
}
