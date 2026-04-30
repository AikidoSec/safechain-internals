//go:build windows

package certconfig

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

// JAVA_TOOL_OPTIONS broadly applies to JVMs launched by the user — direct
// invocations, Maven/Gradle-forked children, JNI-embedded VMs in IDEs — but
// Oracle notes it can be disabled or ignored in some launch/security
// contexts (e.g. setuid/setgid on Unix; equivalent token-mismatch checks on
// Windows). On a normal Windows desktop session running our agent as a
// service this is honored; treat exotic launch contexts as best-effort.
const (
	javaToolOptionsEnvVar  = "JAVA_TOOL_OPTIONS"
	javaTrustStoreFlag     = "-Djavax.net.ssl.trustStore=NUL"
	javaTrustStoreTypeFlag = "-Djavax.net.ssl.trustStoreType=Windows-ROOT"
)

// javaToolOptionsAddition is the exact substring we inject — and look for when
// detecting whether we are already installed or undoing our addition. The
// flags must stay in this order so install/uninstall agree on the marker.
var javaToolOptionsAddition = javaTrustStoreFlag + " " + javaTrustStoreTypeFlag

func installJavaTrust(ctx context.Context) error {
	if err := platform.InstallProxyCAForCurrentUser(ctx, proxy.GetCaCertPath()); err != nil {
		return fmt.Errorf("install SafeChain CA into CurrentUser\\Root: %w", err)
	}

	current, err := platform.GetUserEnvVar(ctx, javaToolOptionsEnvVar)
	if err != nil {
		return fmt.Errorf("read existing JAVA_TOOL_OPTIONS: %w", err)
	}
	if javaToolOptionsAlreadyInstalled(current) {
		return nil
	}
	return platform.SetUserEnvVar(ctx, javaToolOptionsEnvVar, prependJavaToolOptionsAddition(current))
}

func javaNeedsRepair(ctx context.Context) bool {
	current, err := platform.GetUserEnvVar(ctx, javaToolOptionsEnvVar)
	if err != nil {
		return false
	}
	return !javaToolOptionsAlreadyInstalled(current)
}

func uninstallJavaTrust(ctx context.Context) error {
	if err := platform.UninstallProxyCAForCurrentUser(ctx); err != nil {
		// Best-effort: log and continue with the env var cleanup so a stuck
		// certutil doesn't leave JAVA_TOOL_OPTIONS pointing at a store we
		// can no longer service.
		log.Printf("java: failed to remove SafeChain CA from CurrentUser\\Root: %v", err)
	}

	current, err := platform.GetUserEnvVar(ctx, javaToolOptionsEnvVar)
	if err != nil {
		// Best-effort: blindly rewriting JAVA_TOOL_OPTIONS without knowing the
		// current value would clobber unrelated user options (e.g. -Xmx2g),
		// so skip the cleanup rather than surface a fatal error.
		log.Printf("java: failed to read JAVA_TOOL_OPTIONS during uninstall: %v", err)
		return nil
	}
	return platform.SetUserEnvVar(ctx, javaToolOptionsEnvVar, stripJavaToolOptionsAddition(current))
}

func javaToolOptionsAlreadyInstalled(value string) bool {
	value = strings.TrimSpace(value)
	return value == javaToolOptionsAddition || strings.HasPrefix(value, javaToolOptionsAddition+" ")
}

func prependJavaToolOptionsAddition(existing string) string {
	existing = strings.TrimSpace(existing)
	if existing == "" {
		return javaToolOptionsAddition
	}
	return javaToolOptionsAddition + " " + existing
}

func stripJavaToolOptionsAddition(value string) string {
	value = strings.TrimSpace(value)
	if value == javaToolOptionsAddition {
		return ""
	}
	prefix := javaToolOptionsAddition + " "
	if strings.HasPrefix(value, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(value, prefix))
	}
	return value
}
