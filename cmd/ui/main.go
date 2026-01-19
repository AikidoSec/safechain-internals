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
		title         = flag.String("title", "", "Modal title")
		text          = flag.String("text", "", "Modal text content")
		ingress       = flag.String("ingress", "", "Daemon ingress address, to report back when bypass requested.")
		bypassEnabled = flag.Bool("bypass-enabled", false, "Enable bypass requested.")
	)
	flag.Parse()

	if *title == "" || *text == "" || *ingress == "" {
		fmt.Fprintln(os.Stderr, "Usage: safechain-ui --title <title> --text <text> --ingress <ingress>")
		os.Exit(1)
	}

	bypassTrigger := func() {

	}

	if !(*bypassEnabled) {
		// disable bypass trigger.
		bypassTrigger = nil
	}

	if err := ui.ShowBlockedModal(*text, *title, bypassTrigger); err != nil {
		log.Fatalf("Failed to show blocked modal: %v", err)
	}
}
