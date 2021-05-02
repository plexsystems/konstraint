package main

import (
	"log"

	"github.com/plexsystems/konstraint/internal/commands"
	"github.com/spf13/cobra/doc"
)

func main() {
	konstraint := commands.NewDefaultCommand()
	konstraint.DisableAutoGenTag = true
	if err := doc.GenMarkdownTree(konstraint, "./docs/cli"); err != nil {
		log.Fatal(err)
	}
}
