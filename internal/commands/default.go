package commands

import (
	"os"
	"path"

	"github.com/spf13/cobra"
)

// version is set during the build process.
var version = ""

// NewDefaultCommand creates a new default command
func NewDefaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     path.Base(os.Args[0]),
		Short:   "Konstraint",
		Long:    "A tool to create and manage Gatekeeper CRDs from Rego",
		Version: version,
	}

	cmd.AddCommand(newCreateCommand())
	cmd.AddCommand(newDocCommand())

	return &cmd
}
