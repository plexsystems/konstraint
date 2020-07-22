package main

import (
	"log"
	"os"

	"github.com/plexsystems/konstraint/internal/commands"
	"github.com/spf13/cobra/doc"
)

func main() {
	cliDocsDir := "./docs/cli"

	if _, err := os.Stat(cliDocsDir); os.IsNotExist(err) {
		err := os.MkdirAll(cliDocsDir, os.ModePerm)
		if err != nil {
			log.Fatalf("create output directory: %w", err)
		}
	}

	konstraint := commands.NewDefaultCommand()
	err := doc.GenMarkdownTree(konstraint, cliDocsDir)
	if err != nil {
		log.Fatal(err)
	}
}
