package certconfig

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const combinedBundleName = "endpoint-protection-combined-ca.pem"

func combinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), combinedBundleName)
}

func ensureCombinedCABundle(ctx context.Context, extraPaths ...string) (string, error) {
	// The SafeChain CA is the non-negotiable source — fail explicitly if it can't be read.
	safeChainCACertPath := proxy.GetCaCertPath()
	safeChainPayload, err := readAndValidatePEMBundle(safeChainCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SafeChain CA: %w", err)
	}

	// If the user already has NODE_EXTRA_CA_CERTS set (e.g. a corporate CA),
	// include it too so we don't break their existing trust.
	seen := map[string]struct{}{safeChainCACertPath: {}}
	parts := []string{safeChainPayload}

	additionalSources := append([]string{nodeExtraCACertsFromCurrentUser(ctx)}, extraPaths...)
	for _, source := range additionalSources {
		if source == "" {
			continue
		}
		source = utils.ExpandHomePath(strings.TrimSpace(source), platform.GetConfig().HomeDir)
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}

		payload, err := readAndValidatePEMBundle(source)
		if err != nil {
			continue
		}
		parts = append(parts, payload)
	}

	bundlePath := combinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(strings.Join(parts, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("failed to write combined CA bundle %s: %w", bundlePath, err)
	}
	return bundlePath, nil
}

func removeCombinedCABundle() error {
	err := os.Remove(combinedCaBundlePath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove combined CA bundle: %w", err)
	}
	return nil
}

func readAndValidatePEMBundle(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to read symlinked certificate bundle %s", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing to read non-regular certificate bundle %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	normalized := strings.TrimSpace(strings.ReplaceAll(string(data), "\r\n", "\n"))
	if normalized == "" {
		return "", fmt.Errorf("certificate bundle %s is empty", path)
	}

	var (
		rest      = []byte(normalized)
		blocks    []string
		certCount int
	)

	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return "", fmt.Errorf("certificate bundle %s contains non-PEM content", path)
			}
			break
		}

		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("certificate bundle %s contains unsupported PEM block type %q", path, block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", fmt.Errorf("certificate bundle %s contains invalid certificate: %w", path, err)
		}

		blocks = append(blocks, strings.TrimSpace(string(pem.EncodeToMemory(block))))
		certCount++
		rest = remaining
	}

	if certCount == 0 {
		return "", fmt.Errorf("certificate bundle %s does not contain any valid certificates", path)
	}

	return strings.Join(blocks, "\n"), nil
}

func nodeExtraCACertsFromCurrentUser(ctx context.Context) string {
	output, err := runNodeExtraCACertsLookup(ctx)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}
