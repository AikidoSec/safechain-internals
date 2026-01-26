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
		title         = flag.String("title", "", "Modal title")
		subtitle      = flag.String("subtitle", "Installing this package has been blocked because it looks malicious.", "Modal subtitle")
		packageId     = flag.String("package-id", "", "Package identifier to display")
		ingress       = flag.String("ingress", "", "Daemon ingress address, to report back when bypass requested.")
		bypassEnabled = flag.Bool("bypass-enabled", false, "Enable bypass requested.")
	)
	flag.Parse()

	if *title == "" || *subtitle == "" || *ingress == "" || *packageId == "" {
		fmt.Fprintln(os.Stderr, "Usage: safechain-ui --title <title> --subtitle <subtitle> --package-id <id> --ingress <ingress>")
		fmt.Fprintf(os.Stderr, "Arguments provided: %v\n", os.Args[1:])
		os.Exit(1)
	}

	// remove the possible " on macOS.
	trimmedTitle := strings.Trim(*title, "\"")

	bypassTrigger := func() {
		err := sendBypassRequest(*ingress, *packageId)
		if err != nil {
			log.Fatal(err)
		}
	}

	if !(*bypassEnabled) {
		bypassTrigger = nil
	}

	if err := ui.ShowBlockedModal(trimmedTitle, *subtitle, *packageId, WindowTitle, bypassTrigger); err != nil {
		log.Fatalf("Failed to show blocked modal: %v", err)
	}
}
