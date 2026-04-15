//go:build darwin

package certconfig

import (
	"context"
	"errors"
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
	_, err = platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "http.sslCAInfo", c.bundlePath,
	})
	return err
}

func (c *darwinGitTrustConfigurator) Uninstall(ctx context.Context) error {
	gitPath, err := findGitBinary()
	if err != nil {
		log.Printf("git: git not found, skipping http.sslCAInfo cleanup")
		return nil
	}
	current, err := platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "--get", "http.sslCAInfo",
	})
	// exit code 1 means the key is not set — nothing to do.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(current) != c.bundlePath {
		log.Printf("git: http.sslCAInfo points to a different bundle, skipping cleanup")
		return nil
	}
	_, err = platform.RunAsCurrentUser(ctx, gitPath, []string{
		"config", "--global", "--unset", "http.sslCAInfo",
	})
	return err
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
