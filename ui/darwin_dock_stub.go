//go:build !darwin

package main

func keepDockHidden() {
	// No-op on non-macOS; activation policy is macOS-specific.
}
