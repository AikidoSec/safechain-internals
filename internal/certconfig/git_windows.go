//go:build windows

package certconfig

import (
	"context"
	"errors"
	"log"
	"os/exec"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type windowsGitTrustConfigurator struct{}

func newGitTrustConfigurator(_ string) gitTrustConfigurator {
	return &windowsGitTrustConfigurator{}
}

// Install configures git to use the Windows Certificate Store via the schannel
// backend. The SafeChain CA is already installed into the Windows cert store by
// the system trust configurator, so no combined CA bundle file is needed.
func (c *windowsGitTrustConfigurator) Install(ctx context.Context) error {
	gitPath, err := findGitBinary()
	if err != nil {
		log.Printf("git: git not found, skipping http.sslBackend configuration")
		return nil
	}
	_, err = platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "http.sslBackend", "schannel",
	})
	return err
}

func (c *windowsGitTrustConfigurator) Uninstall(ctx context.Context) error {
	gitPath, err := findGitBinary()
	if err != nil {
		log.Printf("git: git not found, skipping http.sslBackend cleanup")
		return nil
	}
	current, err := platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "--get", "http.sslBackend",
	})
	// exit code 1 means the key is not set — nothing to do.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(current) != "schannel" {
		log.Printf("git: http.sslBackend is not schannel, skipping cleanup")
		return nil
	}
	_, err = platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "--unset", "http.sslBackend",
	})
	return err
}

func (c *windowsGitTrustConfigurator) NeedsRepair(ctx context.Context) bool {
	gitPath, err := findGitBinary()
	if err != nil {
		return false
	}
	current, err := platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "--get", "http.sslBackend",
	})
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return true
		}
		return false
	}
	return strings.TrimSpace(current) != "schannel"
}

func findGitBinary() (string, error) {
	return exec.LookPath("git")
}
