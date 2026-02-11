package configure_maven

import (
	"strings"
	"testing"
)

func TestRemoveExistingMavenOpts_RemovesMarkerWrappedBlock(t *testing.T) {
	input := strings.Join(
		[]string{
			"# user config line",
			aikidoMavenOptsBegin,
			"export MAVEN_OPTS=\"-Djavax.net.ssl.trustStoreType=KeychainStore\"",
			aikidoMavenOptsEnd,
			"# trailing",
		},
		"\n",
	)

	out := removeExistingMavenOpts(input)
	if strings.Contains(out, aikidoMavenOptsBegin) || strings.Contains(out, aikidoMavenOptsEnd) {
		t.Fatalf("expected markers to be removed, got: %q", out)
	}
	if strings.Contains(out, "trustStoreType") {
		t.Fatalf("expected MAVEN_OPTS line to be removed, got: %q", out)
	}
	if !strings.Contains(out, "# user config line") || !strings.Contains(out, "# trailing") {
		t.Fatalf("expected non-aikido lines preserved, got: %q", out)
	}
}

func TestRemoveExistingMavenOpts_DoesNotRemoveUserMavenOptsWithoutTruststoreFlags(t *testing.T) {
	input := strings.Join(
		[]string{
			"# user wants their own opts",
			"export MAVEN_OPTS=\"-Xmx2g -Dfoo=bar\"",
		},
		"\n",
	)

	out := removeExistingMavenOpts(input)
	if out != input {
		t.Fatalf("expected user MAVEN_OPTS untouched, got: %q", out)
	}
}

func TestRemoveExistingMavenOpts_DoesNotRemoveUnmarkedTruststoreMavenOpts(t *testing.T) {
	input := strings.Join(
		[]string{
			"# preexisting (unmarked) line",
			"export MAVEN_OPTS=\"-Djavax.net.ssl.trustStoreType=KeychainStore\"",
		},
		"\n",
	)

	out := removeExistingMavenOpts(input)
	if out != input {
		t.Fatalf("expected unmarked MAVEN_OPTS untouched, got: %q", out)
	}
}

func TestRemoveExistingMavenOpts_MissingEndMarkerRemovesToEOF(t *testing.T) {
	input := strings.Join(
		[]string{
			"# before",
			aikidoMavenOptsBegin,
			"export MAVEN_OPTS=\"-Djavax.net.ssl.trustStore=/etc/ssl/certs/ca-certificates.crt\"",
			"# after-but-should-be-removed",
		},
		"\n",
	)

	out := removeExistingMavenOpts(input)
	if strings.Contains(out, "after-but-should-be-removed") {
		t.Fatalf("expected everything after begin marker removed when end is missing, got: %q", out)
	}
	if !strings.Contains(out, "# before") {
		t.Fatalf("expected content before marker preserved, got: %q", out)
	}
}
