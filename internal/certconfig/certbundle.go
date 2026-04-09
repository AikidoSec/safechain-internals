package certconfig

import (
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

func combinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), nodeCombinedBundleName)
}

func pipCombinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), pipCombinedBundleName)
}

// ensureCombinedCABundle writes the combined CA bundle containing the SafeChain CA
// and, if non-empty, the user's pre-existing originalCACertsPath. The SafeChain CA
// is mandatory — the call fails if it can't be read. The original is silently skipped
// on error (missing file, invalid PEM, etc.).
func ensureCombinedCABundle(originalCACertsPath string) (string, error) {
	return ensureCombinedCABundleAt(combinedCaBundlePath(), originalCACertsPath)
}

// ensurePipCombinedCABundle builds the pip CA bundle.
//
// Unlike NODE_EXTRA_CA_CERTS (which appends), PIP_CERT replaces pip's bundle
// entirely. baseCACertsPath must already point to a validated PEM bundle that
// pip should continue trusting after the SafeChain CA is added.
func ensurePipCombinedCABundle(baseCACertsPath string) (string, error) {
	bundlePath := pipCombinedCaBundlePath()

	safeChainCACertPath := proxy.GetCaCertPath()
	safeChainPayload, err := readAndValidatePEMBundle(safeChainCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SafeChain CA: %w", err)
	}

	parts := []string{safeChainPayload}

	expanded := utils.ExpandHomePath(strings.TrimSpace(baseCACertsPath), platform.GetConfig().HomeDir)
	if expanded == "" {
		return "", fmt.Errorf("pip CA bundle path is empty")
	}
	if expanded != safeChainCACertPath && expanded != bundlePath {
		payload, err := readAndValidatePEMBundle(expanded)
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

func ensureCombinedCABundleAt(bundlePath string, originalCACertsPath string) (string, error) {
	safeChainCACertPath := proxy.GetCaCertPath()
	safeChainPayload, err := readAndValidatePEMBundle(safeChainCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SafeChain CA: %w", err)
	}

	parts := []string{safeChainPayload}

	if originalCACertsPath != "" {
		expanded := utils.ExpandHomePath(strings.TrimSpace(originalCACertsPath), platform.GetConfig().HomeDir)
		if expanded != "" && expanded != safeChainCACertPath && expanded != bundlePath {
			if payload, err := readAndValidatePEMBundle(expanded); err == nil {
				parts = append(parts, payload)
			}
		}
	}

	if err := os.WriteFile(bundlePath, []byte(strings.Join(parts, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("failed to write combined CA bundle %s: %w", bundlePath, err)
	}
	return bundlePath, nil
}

func removeCombinedCABundle() error {
	return removeCombinedCABundleAt(combinedCaBundlePath())
}

func removePipCombinedCABundle() error {
	return removeCombinedCABundleAt(pipCombinedCaBundlePath())
}

func removeCombinedCABundleAt(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove combined CA bundle: %w", err)
	}
	return nil
}

func readAndValidatePEMBundle(path string) (string, error) {
	return utils.ReadAndValidatePEMBundle(path)
}
