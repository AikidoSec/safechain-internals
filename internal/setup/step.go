package setup

import "context"

type Step interface {
	InstallName() string
	InstallDescription() string
	UninstallName() string
	UninstallDescription() string
	Install(ctx context.Context) error
	Uninstall(ctx context.Context) error
}
