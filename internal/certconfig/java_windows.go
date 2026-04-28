//go:build windows

package certconfig

import (
	"context"
	"fmt"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

// On Windows, every mainstream JDK ships the SunMSCAPI provider, which can
// expose the Windows certificate store as a JSSE trust store via the
// Windows-ROOT type. Setting JAVA_TOOL_OPTIONS once in HKCU makes every JVM
// launched by the user — direct, IDE-bundled, Maven/Gradle-forked, JNI-embedded
// — read trusted roots from LocalMachine\Root, where platform.InstallProxyCA
// has already placed the SafeChain CA via `certutil -addstore -f Root`.
//
// Caveat: projects that pin -Djavax.net.ssl.trustStore=... in MAVEN_OPTS,
// gradle.properties, or on the command line override our flag (later -D wins
// in JVM argument processing). Per-JDK keytool import is the only fallback;
// add it later if real usage shows the override case is common.
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
	current, err := platform.GetUserEnvVar(ctx, javaToolOptionsEnvVar)
	if err != nil {
		return fmt.Errorf("read existing JAVA_TOOL_OPTIONS: %w", err)
	}
	return platform.SetUserEnvVar(ctx, javaToolOptionsEnvVar, stripJavaToolOptionsAddition(current))
}

func javaToolOptionsAlreadyInstalled(value string) bool {
	value = strings.TrimSpace(value)
	return value == javaToolOptionsAddition || strings.HasPrefix(value, javaToolOptionsAddition+" ")
}

// prependJavaToolOptionsAddition puts our flags before the user's existing
// options. Within JAVA_TOOL_OPTIONS, the JVM applies -D properties left to
// right with later wins, so prepending means an existing user
// -Djavax.net.ssl.trustStore=... still takes effect. We would rather become a
// no-op for that property than silently override a deliberate user choice.
func prependJavaToolOptionsAddition(existing string) string {
	existing = strings.TrimSpace(existing)
	if existing == "" {
		return javaToolOptionsAddition
	}
	return javaToolOptionsAddition + " " + existing
}

// stripJavaToolOptionsAddition removes only the exact leading prefix that
// SafeChain installs. Anything else, including standalone or reordered
// Windows-ROOT flags, is treated as user-managed state and preserved.
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
