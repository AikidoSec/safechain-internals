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

	targets := make([]javaTrustTarget, 0, len(dedupedHomes))
	for _, home := range dedupedHomes {
		target, ok := javaTrustTargetFromHome(home)
		if ok {
			targets = append(targets, target)
		}
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}
