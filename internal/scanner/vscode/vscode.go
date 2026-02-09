package vscode

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/scanner"
)

type VSCodeScanner struct{}

func New() scanner.Scanner {
	return &VSCodeScanner{}
}

func (s *VSCodeScanner) Name() string {
	return "vscode"
}

func (s *VSCodeScanner) Version(ctx context.Context) string {
	return ""
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

func (s *VSCodeScanner) IsInstalled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		return false
	}
}
