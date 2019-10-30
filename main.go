package main

import (
	"os"

	"github.com/plexsystems/konstraint/internal/commands"
)

func main() {
	if err := commands.NewDefaultCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
