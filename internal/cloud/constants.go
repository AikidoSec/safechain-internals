package cloud

const (
	DefaultBaseURL                     = "https://app.aikido.dev"
	HeartbeatEndpoint                  = "api/endpoint_protection/callbacks/reportDeviceHeartbeat"
	SBOMEndpoint                       = "api/endpoint_protection/callbacks/reportInstalledPackages"
	ActivityEndpoint                   = "api/endpoint_protection/callbacks/reportActivity"
	RequestPackageInstallationEndpoint = "api/endpoint_protection/callbacks/requestPackageInstallation"
	UploadDeviceLogsEndpoint           = "api/endpoint_protection/callbacks/uploadDeviceLogs"
)
