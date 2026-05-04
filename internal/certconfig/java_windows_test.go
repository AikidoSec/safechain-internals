//go:build windows

package certconfig

import (
	"strings"
	"testing"
)

func TestPrependJavaToolOptionsAdditionEmpty(t *testing.T) {
	got := prependJavaToolOptionsAddition("")
	if got != javaToolOptionsAddition {
		t.Fatalf("got %q, want %q", got, javaToolOptionsAddition)
	}
}

func TestPrependJavaToolOptionsAdditionPreservesExisting(t *testing.T) {
	existing := "-Xmx2g -Dfile.encoding=UTF-8"
	got := prependJavaToolOptionsAddition(existing)
	wantPrefix := javaToolOptionsAddition + " "
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("expected our flags to be prepended: %q", got)
	}
	if !strings.HasSuffix(got, existing) {
		t.Fatalf("expected existing options preserved at the end: %q", got)
	}
}

func TestPrependJavaToolOptionsAdditionTrimsWhitespace(t *testing.T) {
	got := prependJavaToolOptionsAddition("   -Xmx2g  ")
	if strings.HasSuffix(got, "  ") {
		t.Fatalf("expected trailing whitespace trimmed: %q", got)
	}
	if !strings.HasSuffix(got, "-Xmx2g") {
		t.Fatalf("expected existing options preserved: %q", got)
	}
}

func TestPrependJavaToolOptionsLetsUserTrustStoreOverride(t *testing.T) {
	// User pinned a custom trust store. After prepend, the JVM sees their
	// -Djavax.net.ssl.trustStore=... AFTER ours, and last -D wins — so our
	// addition becomes a no-op for that property, which is the desired
	// behavior. Verify the string ordering reflects that.
	existing := `-Djavax.net.ssl.trustStore=C:\corp\trust.jks`
	got := prependJavaToolOptionsAddition(existing)
	ours := strings.Index(got, javaTrustStoreFlag)
	theirs := strings.Index(got, "C:\\corp\\trust.jks")
	if ours == -1 || theirs == -1 {
		t.Fatalf("missing markers in %q", got)
	}
	if ours >= theirs {
		t.Fatalf("user trustStore must appear after ours so it wins: %q", got)
	}
}

func TestJavaToolOptionsAlreadyInstalled(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty", "", false},
		{"unrelated only", "-Xmx2g", false},
		{"our addition only", javaToolOptionsAddition, true},
		{"our addition with user options", javaToolOptionsAddition + " -Xmx2g", true},
		{"trust store flag without type flag", javaTrustStoreFlag, false},
		{"type flag alone is not ours", javaTrustStoreTypeFlag, false},
		{"alternate trust store type", "-Djavax.net.ssl.trustStoreType=JKS", false},
		{"reordered flags are not treated as healthy", javaTrustStoreTypeFlag + " " + javaTrustStoreFlag, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := javaToolOptionsAlreadyInstalled(tc.value); got != tc.want {
				t.Fatalf("got %v, want %v for %q", got, tc.want, tc.value)
			}
		})
	}
}

func TestCurrentJavaToolOptionsBase(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"empty", "", ""},
		{"our addition alone", javaToolOptionsAddition, ""},
		{"our addition with user options", javaToolOptionsAddition + " -Xmx2g", "-Xmx2g"},
		{"only user options", "-Xmx2g -Dfile.encoding=UTF-8", "-Xmx2g -Dfile.encoding=UTF-8"},
		{"type flag alone remains user-managed", javaTrustStoreTypeFlag, javaTrustStoreTypeFlag},
		{"reordered flags remain user-managed", javaTrustStoreTypeFlag + " " + javaTrustStoreFlag, javaTrustStoreTypeFlag + " " + javaTrustStoreFlag},
		{"embedded exact addition remains user-managed", "-Xmx2g " + javaToolOptionsAddition, "-Xmx2g " + javaToolOptionsAddition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripJavaToolOptionsAddition(tc.value); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
