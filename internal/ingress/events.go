package ingress

type Artifact struct {
	Product        string `json:"product"`
	PackageName    string `json:"identifier"`
	PackageVersion string `json:"version,omitempty"`
}

// BlockEvent represents a blocked request notification from the proxy.
type BlockEvent struct {
	TsMs     int64    `json:"ts_ms"`
	Artifact Artifact `json:"artifact"`
}

type RequestBypassEvent struct {
	Key string `json:"key"`
}
