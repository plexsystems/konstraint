package commands

import (
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewDefaultCommand creates a new default command
func NewDefaultCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     path.Base(os.Args[0]),
		Short:   "Konstraint",
		Long:    "A tool to create and manage Gatekeeper CRDs from Rego",
		Version: "0.4.3",
	}

	// ^$ is for match nothing and do not ignore anything
	ignoreFlagDefault := "^$"
	libFlagDefault := "lib"

	cmd.PersistentFlags().String("ignore", ignoreFlagDefault, "A regex pattern which can be used for ignoring directories and files")
	cmd.PersistentFlags().String("lib", libFlagDefault, "The name of the folder where the Rego librarie(s) are")

	viper.BindPFlag("ignore", cmd.PersistentFlags().Lookup("ignore"))
	viper.BindPFlag("lib", cmd.PersistentFlags().Lookup("lib"))

	cmd.AddCommand(newCreateCommand())
	cmd.AddCommand(newDocCommand())

	return &cmd
}
