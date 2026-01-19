package ingress

// BlockEvent represents a blocked request notification from the proxy.
type BlockEvent struct {
	// e.g. Npm, VSCode, Chrome, PyPI
	Product        string `json:"product"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version,omitempty"`
	Reason         string `json:"reason,omitempty"`
}
