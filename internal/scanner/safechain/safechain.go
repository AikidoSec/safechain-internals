package safechain

import (
	"context"

	"github.com/aikido/sc-agent/internal/scanner"
)

type SafechainScanner struct{}

func New() scanner.Scanner {
	return &SafechainScanner{}
}

func (s *SafechainScanner) Name() string {
	return "safechain"
}

func (s *SafechainScanner) Install(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *SafechainScanner) Uninstall(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *SafechainScanner) IsInstalled(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
		return false, nil
	}
}
