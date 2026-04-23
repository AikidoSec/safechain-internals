package constants

import "time"

const (
	DaemonHeartbeatInterval = 15 * time.Second // Interval at which the daemon will check the if proxy and scanners are running
	LogRotationSizeInBytes  = 10 * 1024 * 1024 // 10 MB
	LogReapingAgeInHours    = 24               // 24 hours
	DaemonStatusLogInterval = 1 * time.Hour
	HeartbeatReportInterval = 3 * time.Minute
	SBOMReportInterval      = 24 * time.Hour
	SetupWizardReshowInterval = 24 * time.Hour
	ProxyStartMaxRetries    = 100
)
