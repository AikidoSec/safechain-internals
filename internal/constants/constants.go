package constants

import "time"

const (
	DaemonHeartbeatInterval = 1 * time.Minute  // Interval at which the daemon will check the if proxy and scanners are running
	LogRotationSizeInBytes  = 10 * 1024 * 1024 // 10 MB
	LogReapingAgeInHours    = 24               // 24 hours
	DaemonStatusLogInterval = 1 * time.Hour
	SBOMReportInterval      = 24 * time.Hour
	ProxyStartMaxRetries    = 20
	ProxyStartRetryInterval = 3 * time.Minute
	CloudHeartbeatInterval  = 30 * time.Minute
)
