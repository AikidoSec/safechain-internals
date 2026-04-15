//go:build darwin

package certconfig

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type darwinGitTrustConfigurator struct {
	bundlePath string
}

func newGitTrustConfigurator(bundlePath string) gitTrustConfigurator {
	return &darwinGitTrustConfigurator{bundlePath: bundlePath}
}

func (c *darwinGitTrustConfigurator) Install(ctx context.Context) error {
	gitPath, err := findGitBinary()
	if err != nil {
		log.Printf("git: git not found, skipping http.sslCAInfo configuration")
		return nil
	}
	baseCACertBundle, err := findSystemGitCABundle()
	if err != nil {
		return fmt.Errorf("git: could not find system CA bundle: %w", err)
	}
	if baseCACertBundle == "" {
		log.Printf("git: no system CA bundle found, skipping http.sslCAInfo configuration")
		return nil
	}
	if _, err := ensureSystemCombinedCABundle(baseCACertBundle); err != nil {
		return err
	}
	_, err = platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "http.sslCAInfo", c.bundlePath,
	})
	return err
}

func (c *darwinGitTrustConfigurator) Uninstall(ctx context.Context) error {
	gitPath, err := findGitBinary()
	if err != nil {
		log.Printf("git: git not found, skipping http.sslCAInfo cleanup")
		return removeSystemCombinedCABundle()
	}
	current, err := platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "--get", "http.sslCAInfo",
	})
	// exit code 1 means the key is not set — nothing to do.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return removeSystemCombinedCABundle()
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(current) != c.bundlePath {
		log.Printf("git: http.sslCAInfo points to a different bundle, skipping cleanup")
	} else {
		if _, err = platform.RunAsCurrentUser(ctx, gitPath, []string{
			"config", "--global", "--unset", "http.sslCAInfo",
		}); err != nil {
			return err
		}
	}
	return removeSystemCombinedCABundle()
}

// findSystemGitCABundle returns the system-level CA bundle that git uses when
// no http.sslCAInfo is configured. On macOS this is the system cert store at
// /private/etc/ssl/cert.pem, which is always present.
func findSystemGitCABundle() (string, error) {
	candidates := []string{
		"/private/etc/ssl/cert.pem",
		"/etc/ssl/cert.pem",
	}
	for _, p := range candidates {
		if _, err := readAndValidatePEMBundle(p); err == nil {
			return p, nil
		}
	}
	return "", nil
}

func findGitBinary() (string, error) {
	return exec.LookPath("git")
}
