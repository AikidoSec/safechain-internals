package ingress

type Artifact struct {
	Product        string `json:"product"`
	PackageName    string `json:"identifier"`
	PackageVersion string `json:"version,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
}

// BlockEvent represents a blocked request notification from the proxy.
type BlockEvent struct {
	ID          string   `json:"id,omitempty"`
	TsMs        int64    `json:"ts_ms"`
	Artifact    Artifact `json:"artifact"`
	BlockReason string   `json:"block_reason"`
	Status      string   `json:"status,omitempty"`
	Count       int      `json:"count,omitempty"`
}

// TlsTerminationFailedEvent represents a TLS MITM handshake failure from the proxy.
type TlsTerminationFailedEvent struct {
	ID      string `json:"id,omitempty"`
	TsMs    int64  `json:"ts_ms"`
	SNI     string `json:"sni"`
	App     string `json:"app,omitempty"`
	AppPath string `json:"app_path,omitempty"`
	Error   string `json:"error"`
}

// MinPackageAgeEvent represents a passive log entry emitted when the proxy
// suppresses versions that do not meet the minimum package age policy.
// Unlike BlockEvent, this is intended for the Logs tab only and should not
// trigger any native popup notification.
type MinPackageAgeEvent struct {
	ID        string   `json:"id,omitempty"`
	TsMs      int64    `json:"ts_ms"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Artifact  Artifact `json:"artifact,omitempty"`
	Title     string   `json:"title,omitempty"`
	Message   string   `json:"message,omitempty"`
}

type AiUsageEvent struct {
	ID       string `json:"id,omitempty"`
	TsMs     int64  `json:"ts_ms"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type EcosystemExceptions struct {
	AllowedPackages  []string `json:"allowed_packages"`
	RejectedPackages []string `json:"rejected_packages"`
}

type EcosystemPermissions struct {
	BlockAllInstalls           bool                `json:"block_all_installs"`
	RequestInstalls            bool                `json:"request_installs"`
	MinimumAllowedAgeTimestamp int64               `json:"minimum_allowed_age_timestamp"`
	Exceptions                 EcosystemExceptions `json:"exceptions"`
}

type PermissionsResponse struct {
	PermissionGroup struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"permission_group"`
	Ecosystems map[string]EcosystemPermissions `json:"ecosystems"`
}
