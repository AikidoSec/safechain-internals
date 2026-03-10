package ingress

type Artifact struct {
	Product        string `json:"product"`
	PackageName    string `json:"identifier"`
	PackageVersion string `json:"version,omitempty"`
}

type BlockReason string

const (
	BlockReasonMalware        BlockReason = "malware"
	BlockReasonRejected       BlockReason = "rejected"
	BlockReasonBlockAll       BlockReason = "block_all"
	BlockReasonRequestInstall BlockReason = "request_install"
)

// BlockEvent represents a blocked request notification from the proxy.
type BlockEvent struct {
	TsMs        int64       `json:"ts_ms"`
	Artifact    Artifact    `json:"artifact"`
	BlockReason BlockReason `json:"block_reason"`
}

type RequestBypassEvent struct {
	Key string `json:"key"`
}
