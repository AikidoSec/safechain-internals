package certconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

type pipTrustConfigurator interface {
	Install(context.Context) error
	Uninstall(context.Context) error
}

type pipConfigurator struct {
	trust pipTrustConfigurator
}

type pipCertSetting struct {
	EnvVar string `json:"env_var"`
	Path   string `json:"path"`
}

func newPipConfigurator() Configurator {
	return &pipConfigurator{
		trust: newPipTrustConfigurator(systemCombinedCaBundlePath()),
	}
}

func (c *pipConfigurator) Name() string {
	return "pip"
}

func originalPipCertPath() string {
	return filepath.Join(platform.GetRunDir(), "endpoint-protection-pip-original-cert-path.txt")
}

func ensureOriginalPipCert(ctx context.Context) (pipCertSetting, error) {
	return ensureOriginalPipCertAt(ctx, originalPipCertPath(), runPipCertLookup)
}

func ensureOriginalPipCertAt(
	ctx context.Context,
	savedPath string,
	lookup func(context.Context) (pipCertSetting, error),
) (pipCertSetting, error) {
	if data, err := os.ReadFile(savedPath); err == nil {
		return parseSavedPipCertSetting(data)
	}

	original, err := lookup(ctx)
	if err != nil {
		return pipCertSetting{}, fmt.Errorf("read existing pip certificate configuration: %w", err)
	}
	original.Path = strings.TrimSpace(original.Path)

	data, err := json.Marshal(original)
	if err != nil {
		return pipCertSetting{}, fmt.Errorf("marshal existing pip certificate configuration: %w", err)
	}
	if err := os.WriteFile(savedPath, data, 0o600); err != nil {
		return pipCertSetting{}, fmt.Errorf("persist existing pip certificate configuration: %w", err)
	}
	return original, nil
}

func (c *pipConfigurator) Install(ctx context.Context) error {
	original, err := ensureOriginalPipCert(ctx)
	if err != nil {
		return err
	}
	baseCACertBundle, err := resolvePipBaseCACertBundle(ctx, original.Path)
	if err != nil {
		return err
	}
	if _, err := ensureSystemCombinedCABundle(baseCACertBundle); err != nil {
		return err
	}
	return c.trust.Install(ctx)
}

func (c *pipConfigurator) Uninstall(ctx context.Context) error {
	if err := c.trust.Uninstall(ctx); err != nil {
		return err
	}
	_ = os.Remove(originalPipCertPath())
	return removeSystemCombinedCABundle()
}

func parseSavedPipCertSetting(data []byte) (pipCertSetting, error) {
	var setting pipCertSetting
	if err := json.Unmarshal(data, &setting); err == nil {
		setting.Path = strings.TrimSpace(setting.Path)
		return setting, nil
	}

	// Backward compatibility with the earlier plain-text format.
	return pipCertSetting{
		EnvVar: pipCertEnvVar,
		Path:   strings.TrimSpace(string(data)),
	}, nil
}

func resolvePipBaseCACertBundle(ctx context.Context, original string) (string, error) {
	return resolvePipBaseCACertBundleAt(ctx, original, findSystemPipCABundle)
}

func resolvePipBaseCACertBundleAt(
	ctx context.Context,
	original string,
	findCertifi func(context.Context) string,
) (string, error) {
	if original != "" {
		return validatePipBaseCABundle(original)
	}

	if certifi := findCertifi(ctx); certifi != "" {
		return validatePipBaseCABundle(certifi)
	}

	return "", fmt.Errorf("no usable pip CA bundle found; refusing to set PIP_CERT without a trusted base bundle")
}

func validatePipBaseCABundle(path string) (string, error) {
	expanded := utils.ExpandHomePath(strings.TrimSpace(path), platform.GetConfig().HomeDir)
	if expanded == "" {
		return "", fmt.Errorf("pip CA bundle path is empty")
	}
	if _, err := readAndValidatePEMBundle(expanded); err != nil {
		return "", fmt.Errorf("pip CA bundle %s is invalid: %w", expanded, err)
	}
	return expanded, nil
}
