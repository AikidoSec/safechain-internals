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

const (
	nodeCombinedBundleName = "endpoint-protection-combined-ca.pem"
	pipCombinedBundleName  = "endpoint-protection-pip-combined-ca.pem"
	gitCombinedBundleName  = "endpoint-protection-git-combined-ca.pem"
)

func combinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), nodeCombinedBundleName)
}

func pipCombinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), pipCombinedBundleName)
}

func gitCombinedCaBundlePath() string {
	return filepath.Join(platform.GetRunDir(), gitCombinedBundleName)
}

// ensureCombinedCABundle writes the combined CA bundle containing the SafeChain CA
// and, if non-empty, the user's pre-existing originalCACertsPath. The SafeChain CA
// is mandatory — the call fails if it can't be read. The original is silently skipped
// on error (missing file, invalid PEM, etc.).
func ensureCombinedCABundle(originalCACertsPath string) (string, error) {
	return ensureCombinedCABundleAt(combinedCaBundlePath(), originalCACertsPath)
}

func ensurePipCombinedCABundle(baseCACertsPath string) (string, error) {
	return ensureReplacementCABundleAt(pipCombinedCaBundlePath(), baseCACertsPath)
}

func ensureGitCombinedCABundle(baseCACertsPath string) (string, error) {
	return ensureReplacementCABundleAt(gitCombinedCaBundlePath(), baseCACertsPath)
}

// ensureReplacementCABundleAt writes a PEM file at bundlePath that concatenates
// the SafeChain CA (first) and the contents of baseCACertsPath (second).
//
// It is intended for tools that accept a single CA bundle path and use it as
// their complete trust store — replacing rather than appending to the default
// (e.g. PIP_CERT, git http.sslCAInfo). Both the SafeChain CA and baseCACertsPath
// are required: if either is missing or invalid the call returns an error and
// no file is written.
//
// Returns the path of the written bundle on success.
func ensureReplacementCABundleAt(bundlePath, baseCACertsPath string) (string, error) {
	safeChainCACertPath := proxy.GetCaCertPath()
	safeChainPayload, err := readAndValidatePEMBundle(safeChainCACertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SafeChain CA: %w", err)
	}

	parts := []string{safeChainPayload}

	expanded := utils.ExpandHomePath(strings.TrimSpace(baseCACertsPath), platform.GetConfig().HomeDir)
	if expanded == "" {
		return "", fmt.Errorf("base CA bundle path is empty")
	}
	if expanded != safeChainCACertPath && expanded != bundlePath {
		payload, err := readAndValidatePEMBundle(expanded)
		if err != nil {
			return "", fmt.Errorf("failed to read base CA bundle: %w", err)
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

func removeGitCombinedCABundle() error {
	return removeCombinedCABundleAt(gitCombinedCaBundlePath())
}

func removeCombinedCABundleAt(path string) error {
	err := os.Remove(path)
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
