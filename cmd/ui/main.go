package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/ui"
)

const WindowTitle = "SafeChain Ultimate"

func main() {
	var (
		title            = flag.String("title", "", "Modal title")
		subtitle         = flag.String("subtitle", "Installing this package has been blocked because it looks malicious.", "Modal subtitle")
		ingress          = flag.String("ingress", "", "Daemon ingress address, to report back when bypass requested.")
		bypassEnabled    = flag.Bool("bypass-enabled", false, "Enable bypass requested.")
		product          = flag.String("product", "", "Package ecosystem")
		packageId        = flag.String("package-id", "", "Package identifier e.g. express")
		packageVersion   = flag.String("package-version", "", "Package version e.g. 1.0.0")
		packageHumanName = flag.String("package-human-name", "", "Human-readable package name")
	)
	flag.Parse()

	if *title == "" || *subtitle == "" || *ingress == "" || *packageId == "" {
		fmt.Fprintln(os.Stderr, "Usage: safechain-ui --title <title> --subtitle <subtitle> --package-id <id> --ingress <ingress>")
		fmt.Fprintf(os.Stderr, "Arguments provided: %v\n", os.Args[1:])
		os.Exit(1)
	}

	// remove the possible " on macOS.
	trimmedTitle := strings.Trim(*title, "\"")
	trimmedSubtitle := strings.Trim(*subtitle, "\"")

	bypassTrigger := func() {
		err := sendBypassRequest(*ingress, *packageId, *product, *packageId, *packageHumanName, *packageVersion)
		if err != nil {
			log.Fatal(err)
		}
	}

	if !(*bypassEnabled) {
		bypassTrigger = nil
	}

	if err := ui.ShowBlockedModal(trimmedTitle, trimmedSubtitle, *packageId, *packageVersion, *packageHumanName, WindowTitle, bypassTrigger); err != nil {
		log.Fatalf("Failed to show blocked modal: %v", err)
	}
}
