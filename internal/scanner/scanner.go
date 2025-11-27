package scanner

import (
	"context"
)

// Scanner defines the interface for protection engine scanners
type Scanner interface {
	// Name returns the name of the scanner
	Name() string

	// Install installs the scanner protection engine
	Install(ctx context.Context) error

	// Uninstall removes the scanner protection engine
	Uninstall(ctx context.Context) error

	// IsInstalled checks if the scanner is currently installed
	IsInstalled(ctx context.Context) (bool, error)
}
