package version

import (
	"encoding/json"
	"runtime"
)

type VersionInfo struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
	GoVersion string `json:"go_version"`
}

var (
	Version   = "1.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"

	Info = &VersionInfo{
		Version:   Version,
		BuildTime: BuildTime,
		GitCommit: GitCommit,
		GoVersion: runtime.Version(),
	}
)

func (v *VersionInfo) String() string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
