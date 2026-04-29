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

// On Windows, most mainstream OpenJDK/Oracle-derived JDKs ship the SunMSCAPI
// provider, which exposes Windows certificate stores to JSSE. We point the
// JVM at the type "Windows-ROOT", which maps to the current user's root store
// (CurrentUser\Root). That choice gives us two things:
//
//   - Coverage: Windows-ROOT has been part of SunMSCAPI since JDK 1.6, so
//     every realistic JDK on the machine recognizes it (no JDK 11.0.20 /
//     17.0.8 backport requirement, no surprise failures on JDK 8).
//   - Scope: per-user trust, not machine-wide. If multiple users share the
//     box, our MITM CA is only trusted by the active user that the agent
//     runs setup for.
//
// platform.InstallProxyCA already places the SafeChain CA in
// LocalMachine\Root via `certutil -addstore -f Root` (LocalSystem-scope) for
// the rest of the trust pipeline (browsers, schannel, etc.). For Java to see
// it via Windows-ROOT we additionally mirror the cert into the active user's
// HKCU\...\Root store via platform.InstallProxyCAForCurrentUser.
//
// JAVA_TOOL_OPTIONS broadly applies to JVMs launched by the user — direct
// invocations, Maven/Gradle-forked children, JNI-embedded VMs in IDEs — but
// Oracle notes it can be disabled or ignored in some launch/security
// contexts (e.g. setuid/setgid on Unix; equivalent token-mismatch checks on
// Windows). On a normal Windows desktop session running our agent as a
// service this is honored; treat exotic launch contexts as best-effort.
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
