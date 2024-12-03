package commands

import (
	"fmt"
	"os"
	"path"

	"github.com/spf13/cobra"
)

// version is set during the build process.
var version string

// NewDefaultCommand creates a new default command
func NewDefaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     path.Base(os.Args[0]),
		Short:   "Konstraint",
		Long:    "A tool to create and manage Gatekeeper CRDs from Rego",
		Version: fmt.Sprintf("Version: %s\n", version),
	}

	cmd.SetVersionTemplate(`{{.Version}}`)

	cmd.AddCommand(newCreateCommand())
	cmd.AddCommand(newDocCommand())

	return &cmd
}
