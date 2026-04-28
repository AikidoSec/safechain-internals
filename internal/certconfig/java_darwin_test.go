//go:build darwin

package certconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDarwinJavaHomeList(t *testing.T) {
	output := `Matching Java Virtual Machines (2):
    21.0.2 (arm64) "Amazon Corretto 21" - "Amazon Corretto 21" /Users/test/Library/Java/JavaVirtualMachines/corretto-21.0.2/Contents/Home
    17.0.10 (arm64) "Eclipse Temurin 17" - "Eclipse Temurin 17" /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
`

	got := parseDarwinJavaHomeList(output)
	want := []string{
		"/Users/test/Library/Java/JavaVirtualMachines/corretto-21.0.2/Contents/Home",
		"/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected homes: got %q want %q", got, want)
	}
}

func TestJavaTrustTargetFromHome(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "lib", "security"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bin", "keytool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "lib", "security", "cacerts"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	target, ok := javaTrustTargetFromHome(home)
	if !ok {
		t.Fatal("expected valid trust target")
	}
	if target.cacertsPath != filepath.Join(home, "lib", "security", "cacerts") {
		t.Fatalf("unexpected cacerts path: %s", target.cacertsPath)
	}
}

func TestJavaHomesFromJetBrains(t *testing.T) {
	home := t.TempDir()

	userJDK := filepath.Join(home, "Library", "Java", "JavaVirtualMachines", "corretto-21", "Contents", "Home")
	ideJDK := filepath.Join(home, "Library", "Application Support", "JetBrains", "IntelliJIdea2024.3", "jdks", "temurin-21", "Contents", "Home")
	unrelated := filepath.Join(home, "Library", "Application Support", "JetBrains", "IntelliJIdea2024.3", "settings")

	for _, dir := range []string{userJDK, ideJDK, unrelated} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got := javaHomesFromJetBrains(home)
	want := map[string]bool{userJDK: true, ideJDK: true}

	if len(got) != len(want) {
		t.Fatalf("got %d homes, want %d: %v", len(got), len(want), got)
	}
	for _, h := range got {
		if !want[h] {
			t.Fatalf("unexpected home in result: %s", h)
		}
	}
}

func TestJavaHomesFromJetBrains_EmptyHome(t *testing.T) {
	if got := javaHomesFromJetBrains(""); got != nil {
		t.Fatalf("expected nil for empty homeDir, got %v", got)
	}
}

func TestJavaHomesFromVersionManagers(t *testing.T) {
	home := t.TempDir()

	sdkmanJDK := filepath.Join(home, ".sdkman", "candidates", "java", "21.0.5-tem")
	asdfJDK := filepath.Join(home, ".asdf", "installs", "java", "openjdk-21.0.1")
	jenvJDK := filepath.Join(home, ".jenv", "versions", "21.0")
	unrelated := filepath.Join(home, ".sdkman", "candidates", "java", "current") // current is a symlink in real installs; treat as plain dir here

	for _, dir := range []string{sdkmanJDK, asdfJDK, jenvJDK, unrelated} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got := javaHomesFromVersionManagers(home)
	want := map[string]bool{sdkmanJDK: true, asdfJDK: true, jenvJDK: true, unrelated: true}

	if len(got) != len(want) {
		t.Fatalf("got %d homes, want %d: %v", len(got), len(want), got)
	}
	for _, h := range got {
		if !want[h] {
			t.Fatalf("unexpected home in result: %s", h)
		}
	}
}

func TestJavaHomesFromVersionManagers_EmptyHome(t *testing.T) {
	if got := javaHomesFromVersionManagers(""); got != nil {
		t.Fatalf("expected nil for empty homeDir, got %v", got)
	}
}

func TestCollectDarwinJavaTrustTargets(t *testing.T) {
	homes := []string{
		filepath.Join(t.TempDir(), "corretto-19.0.2", "Contents", "Home"),
		filepath.Join(t.TempDir(), "temurin-21.jdk", "Contents", "Home"),
	}

	for _, home := range homes {
		if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(home, "lib", "security"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "bin", "keytool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "lib", "security", "cacerts"), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]struct{}{}
	var dedupedHomes []string
	for _, home := range homes {
		dedupedHomes = appendIfMissingCanonicalHome(dedupedHomes, seen, home)
	}

	jdkTargets := make([]javaTrustTarget, 0, len(dedupedHomes))
	for _, home := range dedupedHomes {
		target, ok := javaTrustTargetFromHome(home)
		if ok {
			jdkTargets = append(jdkTargets, target)
		}
	}
	if len(jdkTargets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(jdkTargets))
	}
}
