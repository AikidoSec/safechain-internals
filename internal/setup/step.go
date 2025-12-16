package setup

import "context"

type Step interface {
	Name() string
	Description() string
	Run(ctx context.Context) error
}
