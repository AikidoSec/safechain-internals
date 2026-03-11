package ingress

type Artifact struct {
	Product        string `json:"product"`
	PackageName    string `json:"identifier"`
	PackageVersion string `json:"version,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
}

// BlockEvent represents a blocked request notification from the proxy.
type BlockEvent struct {
	TsMs        int64    `json:"ts_ms"`
	Artifact    Artifact `json:"artifact"`
	BlockReason string   `json:"block_reason"`
}

type RequestBypassEvent struct {
	Product        string `json:"product"`
	PackageId      string `json:"package_id"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}
