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
}

// TlsTerminationFailedEvent represents a TLS MITM handshake failure from the proxy.
type TlsTerminationFailedEvent struct {
	ID    string `json:"id,omitempty"`
	TsMs  int64  `json:"ts_ms"`
	SNI   string `json:"sni"`
	App   string `json:"app,omitempty"`
	Error string `json:"error"`
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
