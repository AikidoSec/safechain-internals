package pip

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

type trustConfigurator interface {
	Install(context.Context) error
	Uninstall(context.Context) error
}

type Configurator struct {
	trust trustConfigurator
}

type CertSetting struct {
	EnvVar string `json:"env_var"`
	Path   string `json:"path"`
}

func New() *Configurator {
	return &Configurator{
		trust: newTrustConfigurator(shared.PipCombinedCaBundlePath()),
	}
}

func (c *Configurator) Name() string {
	return "pip"
}

func originalCertPath() string {
	return filepath.Join(platform.GetRunDir(), "endpoint-protection-pip-original-cert-path.txt")
}

func ensureOriginalCert(ctx context.Context) (CertSetting, error) {
	return ensureOriginalCertAt(ctx, originalCertPath(), runCertLookup)
}

func ensureOriginalCertAt(
	ctx context.Context,
	savedPath string,
	lookup func(context.Context) (CertSetting, error),
) (CertSetting, error) {
	if data, err := os.ReadFile(savedPath); err == nil {
		return parseSavedCertSetting(data)
	}

	original, err := lookup(ctx)
	if err != nil {
		return CertSetting{}, fmt.Errorf("read existing pip certificate configuration: %w", err)
	}
	original.Path = strings.TrimSpace(original.Path)

	data, err := json.Marshal(original)
	if err != nil {
		return CertSetting{}, fmt.Errorf("marshal existing pip certificate configuration: %w", err)
	}
	if err := os.WriteFile(savedPath, data, 0o600); err != nil {
		return CertSetting{}, fmt.Errorf("persist existing pip certificate configuration: %w", err)
	}
	return original, nil
}

func (c *Configurator) Install(ctx context.Context) error {
	original, err := ensureOriginalCert(ctx)
	if err != nil {
		return err
	}
	baseCACertBundle, err := resolveBaseCACertBundle(ctx, original.Path)
	if err != nil {
		return err
	}
	if _, err := shared.EnsurePipCombinedCABundle(baseCACertBundle); err != nil {
		return err
	}
	return c.trust.Install(ctx)
}

func (c *Configurator) Uninstall(ctx context.Context) error {
	if err := c.trust.Uninstall(ctx); err != nil {
		return err
	}
	_ = os.Remove(originalCertPath())
	return shared.RemovePipCombinedCABundle()
}

func parseSavedCertSetting(data []byte) (CertSetting, error) {
	var setting CertSetting
	if err := json.Unmarshal(data, &setting); err == nil {
		setting.Path = strings.TrimSpace(setting.Path)
		return setting, nil
	}

	// Backward compatibility with the earlier plain-text format.
	return CertSetting{
		EnvVar: CertEnvVar,
		Path:   strings.TrimSpace(string(data)),
	}, nil
}

func resolveBaseCACertBundle(ctx context.Context, original string) (string, error) {
	return resolveBaseCACertBundleAt(ctx, original, findSystemCABundle)
}

func resolveBaseCACertBundleAt(
	ctx context.Context,
	original string,
	findCertifi func(context.Context) string,
) (string, error) {
	if original != "" {
		return validateBaseCABundle(original)
	}

	if certifi := findCertifi(ctx); certifi != "" {
		return validateBaseCABundle(certifi)
	}

	return "", fmt.Errorf("no usable pip CA bundle found; refusing to set PIP_CERT without a trusted base bundle")
}

func validateBaseCABundle(path string) (string, error) {
	expanded := utils.ExpandHomePath(strings.TrimSpace(path), platform.GetConfig().HomeDir)
	if expanded == "" {
		return "", fmt.Errorf("pip CA bundle path is empty")
	}
	if _, err := shared.ReadAndValidatePEMBundle(expanded); err != nil {
		return "", fmt.Errorf("pip CA bundle %s is invalid: %w", expanded, err)
	}
	return expanded, nil
}
