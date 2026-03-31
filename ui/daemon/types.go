package daemon

import "fmt"

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

// Validate ensures the BlockedEvent satisfies daemon API contract
// requirements before transmission or processing.
func (e *BlockEvent) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("missing or empty required field: id")
	}
	if e.TsMs == 0 {
		return fmt.Errorf("missing or empty required field: ts")
	}
	if e.Artifact.Product == "" {
		return fmt.Errorf("missing or empty required field: product")
	}
	if e.Artifact.PackageName == "" {
		return fmt.Errorf("missing or empty required field: identifier")
	}
	return nil
}

// TlsTerminationFailedEvent represents a TLS MITM handshake failure.
type TlsTerminationFailedEvent struct {
	ID    string `json:"id,omitempty"`
	TsMs  int64  `json:"ts_ms"`
	SNI   string `json:"sni"`
	App   string `json:"app,omitempty"`
	Error string `json:"error"`
}

func (e *TlsTerminationFailedEvent) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("missing or empty required field: id")
	}
	if e.TsMs == 0 {
		return fmt.Errorf("missing or empty required field: ts_ms")
	}
	if e.SNI == "" {
		return fmt.Errorf("missing or empty required field: sni")
	}
	return nil
}
