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
		title         = flag.String("title", "SafeChain Ultimate", "Modal title")
		text          = flag.String("text", "", "Modal text content")
		packageId     = flag.String("package-id", "", "Package identifier to display")
		ingress       = flag.String("ingress", "", "Daemon ingress address, to report back when bypass requested.")
		bypassEnabled = flag.Bool("bypass-enabled", false, "Enable bypass requested.")
	)
	flag.Parse()

	if *title == "" || *text == "" || *ingress == "" {
		fmt.Fprintln(os.Stderr, "Usage: safechain-ui --title <title> --text <text> --package-id <id> --ingress <ingress>")
		os.Exit(1)
	}

	bypassTrigger := func() {
		err := sendBypassRequest(*ingress, *packageId)
		if err != nil {
			log.Fatal(err)
		}
	}

	if !(*bypassEnabled) {
		bypassTrigger = nil
	}

	if err := ui.ShowBlockedModal(*text, *packageId, *title, bypassTrigger); err != nil {
		log.Fatalf("Failed to show blocked modal: %v", err)
	}
}
