package daemon

import "fmt"

// BlockedEvent matches the daemon API response.
type BlockedEvent struct {
	ID string `json:"id"`
	Ts string `json:"ts"`
	// The product type (e.g., "npm", "pypi", "vscode", "chrome")
	Product string `json:"product"`
	// The name or identifier of the artifact
	PackageName string `json:"identifier"`
	// Optional version
	PackageVersion string `json:"version,omitempty"`
	BypassEnabled  bool   `json:"bypass_enabled"`
}

// Validate returns an error if any required field is missing or empty.
func (e *BlockedEvent) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("missing or empty required field: id")
	}
	if e.Ts == "" {
		return fmt.Errorf("missing or empty required field: ts")
	}
	if e.Product == "" {
		return fmt.Errorf("missing or empty required field: product")
	}
	if e.PackageName == "" {
		return fmt.Errorf("missing or empty required field: identifier")
	}
	return nil
}
