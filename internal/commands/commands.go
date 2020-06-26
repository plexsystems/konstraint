package commands

import (
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	IgnoreFlagDefault    = "^$"
	LibraryFolderDefault = "lib"
)

// NewDefaultCommand creates a new default command
func NewDefaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   path.Base(os.Args[0]),
		Short: "Konstraint",
		Long:  "A CLI tool to create and manage Gatekeeper CRDs from Rego",
	}

	cmd.PersistentFlags().String("ignore", IgnoreFlagDefault, "A regex pattern which can be used for ignoring directories and files")
	cmd.PersistentFlags().String("lib", LibraryFolderDefault, "The name of the folder where the Rego libarie(s) are")

	viper.BindPFlag("ignore", cmd.PersistentFlags().Lookup("ignore"))
	viper.BindPFlag("lib", cmd.PersistentFlags().Lookup("lib"))

	cmd.AddCommand(NewCreateCommand())
	cmd.AddCommand(NewDocCommand())

	return &cmd
}
