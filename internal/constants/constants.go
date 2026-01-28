package constants

import "time"

const (
	DaemonHeartbeatInterval = 1 * time.Minute  // Interval at which the daemon will check the if proxy and scanners are running
	LogRotationSizeInBytes  = 10 * 1024 * 1024 // 10 MB
	LogReapingAgeInHours    = 24               // 24 hours
)
