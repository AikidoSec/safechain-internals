package scanner

import (
	"context"
)

type Scanner interface {
	Name() string
	Version(ctx context.Context) string
	Install(ctx context.Context) error
	Uninstall(ctx context.Context) error
	IsInstalled(ctx context.Context) bool
}
