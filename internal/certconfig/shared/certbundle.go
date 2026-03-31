package shared

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

const (
	nodeCombinedBundleName = "endpoint-protection-combined-ca.pem"
	pipCombinedBundleName  = "endpoint-protection-pip-combined-ca.pem"
)

func CombinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), nodeCombinedBundleName)
}

func PipCombinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), pipCombinedBundleName)
}

// EnsureCombinedCABundle writes the combined CA bundle containing the SafeChain CA
// and, if non-empty, the user's pre-existing originalCACertsPath. The SafeChain CA
// is mandatory — the call fails if it can't be read. The original is silently skipped
// on error (missing file, invalid PEM, etc.).
func EnsureCombinedCABundle(originalCACertsPath string) (string, error) {
	return EnsureCombinedCABundleAt(CombinedCaBundlePath(), originalCACertsPath)
}

// EnsurePipCombinedCABundle builds the pip CA bundle.
//
// Unlike NODE_EXTRA_CA_CERTS (which appends), PIP_CERT replaces pip's bundle
// entirely. baseCACertsPath must already point to a validated PEM bundle that
// pip should continue trusting after the SafeChain CA is added.
func EnsurePipCombinedCABundle(baseCACertsPath string) (string, error) {
	bundlePath := PipCombinedCaBundlePath()

	safeChainCACertPath := proxy.GetCaCertPath()
	safeChainPayload, err := ReadAndValidatePEMBundle(safeChainCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SafeChain CA: %w", err)
	}

	parts := []string{safeChainPayload}

	expanded := utils.ExpandHomePath(strings.TrimSpace(baseCACertsPath), platform.GetConfig().HomeDir)
	if expanded == "" {
		return "", fmt.Errorf("pip CA bundle path is empty")
	}
	if expanded != safeChainCACertPath && expanded != bundlePath {
		payload, err := ReadAndValidatePEMBundle(expanded)
		if err != nil {
			return "", fmt.Errorf("failed to read pip base CA bundle: %w", err)
		}
		parts = append(parts, payload)
	}

	if err := os.WriteFile(bundlePath, []byte(strings.Join(parts, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("failed to write combined CA bundle %s: %w", bundlePath, err)
	}
	return bundlePath, nil
}

func EnsureCombinedCABundleAt(bundlePath string, originalCACertsPath string) (string, error) {
	safeChainCACertPath := proxy.GetCaCertPath()
	safeChainPayload, err := ReadAndValidatePEMBundle(safeChainCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SafeChain CA: %w", err)
	}

	parts := []string{safeChainPayload}

	if originalCACertsPath != "" {
		expanded := utils.ExpandHomePath(strings.TrimSpace(originalCACertsPath), platform.GetConfig().HomeDir)
		if expanded != "" && expanded != safeChainCACertPath && expanded != bundlePath {
			if payload, err := ReadAndValidatePEMBundle(expanded); err == nil {
				parts = append(parts, payload)
			}
		}
	}

	if err := os.WriteFile(bundlePath, []byte(strings.Join(parts, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("failed to write combined CA bundle %s: %w", bundlePath, err)
	}
	return bundlePath, nil
}

func RemoveCombinedCABundle() error {
	return RemoveCombinedCABundleAt(CombinedCaBundlePath())
}

func RemovePipCombinedCABundle() error {
	return RemoveCombinedCABundleAt(PipCombinedCaBundlePath())
}

func RemoveCombinedCABundleAt(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove combined CA bundle: %w", err)
	}
	return nil
}

func ReadAndValidatePEMBundle(path string) (string, error) {
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

		// Include the certificate regardless of whether Go's strict x509 parser
		// accepts it — legacy root CAs (e.g. negative serial numbers) are valid
		// for OpenSSL/pip but rejected by Go. We still parse to catch genuinely
		// malformed DER; those are skipped rather than failing the whole bundle.
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			rest = remaining
			continue
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
