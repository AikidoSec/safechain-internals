package githook

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/scanner"
)

type GitHookScanner struct{}

func New() scanner.Scanner {
	return &GitHookScanner{}
}

func (s *GitHookScanner) Name() string {
	return "githook"
}

func (s *GitHookScanner) Install(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *GitHookScanner) Uninstall(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *GitHookScanner) IsInstalled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		return false
	}
}
