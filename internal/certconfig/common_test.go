package certconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

func TestWriteManagedBlockReplacesExistingBlock(t *testing.T) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.txt")
	format := managedBlockFormat{
		startMarker: "# start",
		endMarker:   "# end",
	}

	initial := strings.Join([]string{
		"before",
		"# start",
		"old",
		"# end",
		"after",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeManagedBlock(path, "new", 0o644, format); err != nil {
		t.Fatalf("writeManagedBlock failed: %v", err)
	}

	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)

	if strings.Contains(got, "\nold\n") {
		t.Fatalf("expected old managed block to be replaced, got %q", got)
	}
	if !strings.Contains(got, "# start\nnew\n# end\n") {
		t.Fatalf("expected new managed block in output, got %q", got)
	}
	if !strings.Contains(got, "before\nafter\n") {
		t.Fatalf("expected unmanaged content preserved, got %q", got)
	}
}

func TestWriteManagedBlockPreservesCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.txt")
	format := managedBlockFormat{
		startMarker: "# start",
		endMarker:   "# end",
	}

	initial := "before\r\nafter\r\n"
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeManagedBlock(path, "line1\nline2", 0o644, format); err != nil {
		t.Fatalf("writeManagedBlock failed: %v", err)
	}

	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)

	if !strings.Contains(got, "\r\n# start\r\nline1\r\nline2\r\n# end\r\n") {
		t.Fatalf("expected CRLF-managed block, got %q", got)
	}
}

func TestRemoveManagedBlockRemovesOnlyManagedSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.txt")
	format := managedBlockFormat{
		startMarker: "# start",
		endMarker:   "# end",
	}

	initial := strings.Join([]string{
		"before",
		"# start",
		"managed",
		"# end",
		"after",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := utils.RemoveManagedBlock(path, 0o644, format.startMarker, format.endMarker); err != nil {
		t.Fatalf("RemoveManagedBlock failed: %v", err)
	}

	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)

	if strings.Contains(got, "# start") || strings.Contains(got, "managed") {
		t.Fatalf("expected managed block removed, got %q", got)
	}
	if !strings.Contains(got, "before\nafter") {
		t.Fatalf("expected unmanaged content preserved, got %q", got)
	}
}
