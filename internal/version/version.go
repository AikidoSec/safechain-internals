package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the version of the application
	Version = "dev"
	// BuildTime is the time when the binary was built
	BuildTime = "unknown"
	// GitCommit is the git commit hash
	GitCommit = "unknown"
	// GoVersion is the Go version used to build
	GoVersion = runtime.Version()
)

// Info returns version information as a string
func Info() string {
	return fmt.Sprintf("Version: %s\nBuild Time: %s\nGit Commit: %s\nGo Version: %s",
		Version, BuildTime, GitCommit, GoVersion)
}
