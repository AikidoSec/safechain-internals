package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/AikidoSec/safechain-agent/internal/ui"
)

func main() {
	var (
		product        = flag.String("product", "", "Product name (e.g., Npm, VSCode)")
		packageName    = flag.String("package", "", "Package name that was blocked")
		packageVersion = flag.String("version", "", "Package version (optional)")
	)
	flag.Parse()

	if *product == "" || *packageName == "" {
		fmt.Fprintln(os.Stderr, "Usage: safechain-ui --product <product> --package <name> [--version <version>]")
		os.Exit(1)
	}

	title := "SafeChain Ultimate - Blocked malware."

	var text string
	if *packageVersion != "" {
		text = fmt.Sprintf(
			"SafeChain blocked a potentially malicious %s package:\n\n%s@%s",
			*product,
			*packageName,
			*packageVersion,
		)
	} else {
		text = fmt.Sprintf(
			"SafeChain blocked a potentially malicious %s package:\n\n%s",
			*product,
			*packageName,
		)
	}

	if err := ui.ShowBlockedModal(text, title, nil); err != nil {
		log.Fatalf("Failed to show blocked modal: %v", err)
	}
}
