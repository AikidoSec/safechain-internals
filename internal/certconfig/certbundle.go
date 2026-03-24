package certconfig

import (
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

// ensureCombinedCABundle writes the combined CA bundle containing the SafeChain CA
// and, if non-empty, the user's pre-existing originalCACertsPath. The SafeChain CA
// is mandatory — the call fails if it can't be read. The original is silently skipped
// on error (missing file, invalid PEM, etc.).
func ensureCombinedCABundle(originalCACertsPath string) (string, error) {
	safeChainCACertPath := proxy.GetCaCertPath()
	safeChainPayload, err := readAndValidatePEMBundle(safeChainCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SafeChain CA: %w", err)
	}

	parts := []string{safeChainPayload}

	if originalCACertsPath != "" {
		expanded := utils.ExpandHomePath(strings.TrimSpace(originalCACertsPath), platform.GetConfig().HomeDir)
		if expanded != "" && expanded != safeChainCACertPath && expanded != combinedCaBundlePath() {
			if payload, err := readAndValidatePEMBundle(expanded); err == nil {
				parts = append(parts, payload)
			}
		}
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
