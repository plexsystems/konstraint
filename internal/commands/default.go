package commands

import (
	"fmt"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			switch viper.GetString("log-level") {
			case "debug":
				log.SetLevel(log.DebugLevel)
			case "info":
				log.SetLevel(log.InfoLevel)
			case "warn":
				log.SetLevel(log.WarnLevel)
			case "error":
				log.SetLevel(log.ErrorLevel)
			default:
				return fmt.Errorf("log-level is invalid: %s", viper.GetString("log-level"))
			}

			return nil
		},
	}

	cmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")
	if err := viper.BindPFlag("log-level", cmd.PersistentFlags().Lookup("log-level")); err != nil {
		log.Fatalf("bind log-level flag: %v", err)
	}

	cmd.SetVersionTemplate(`{{.Version}}`)

	cmd.AddCommand(newCreateCommand())
	cmd.AddCommand(newDocCommand())

	return &cmd
}
