package vscode

import (
	"context"

	"github.com/AikidoSec/safechain-agent/internal/scanner"
)

type VSCodeScanner struct{}

func New() scanner.Scanner {
	return &VSCodeScanner{}
}

func (s *VSCodeScanner) Name() string {
	return "vscode"
}

func (s *VSCodeScanner) Install(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *VSCodeScanner) Uninstall(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *VSCodeScanner) IsInstalled(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
		return false, nil
	}
}
