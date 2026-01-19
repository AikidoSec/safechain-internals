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
		title = flag.String("title", "", "Modal title")
		text  = flag.String("text", "", "Modal text content")
	)
	flag.Parse()

	if *title == "" || *text == "" {
		fmt.Fprintln(os.Stderr, "Usage: safechain-ui --title <title> --text <text>")
		os.Exit(1)
	}

	if err := ui.ShowBlockedModal(*text, *title, nil); err != nil {
		log.Fatalf("Failed to show blocked modal: %v", err)
	}
}
