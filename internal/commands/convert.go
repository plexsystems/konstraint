package commands

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/plexsystems/konstraint/internal/rego"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newConvertCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "convert <dir>",
		Short: "Convert old style annotations to OPA Rich Metadata Annotations",
		Example: `Convert all found policies inplace

konstraint convert examples`,

		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runConvertCommand(path)
		},
	}

	return &cmd
}

func runConvertCommand(path string) error {
	regos, err := rego.GetAllSeveritiesWithoutImports(path)
	if err != nil {
		return fmt.Errorf("get regos: %w", err)
	}

	for _, r := range regos {
		logger := log.WithFields(log.Fields{
			"name": r.Kind(),
			"src":  r.Path(),
		})

		if !r.HasLegacyAnnotations() {
			continue
		}

		conveted, err := r.ConvertLegacyAnnotations()
		if err != nil {
			logger.WithError(err).Error("cant convert legacy annotations")
		}

		var sb strings.Builder
		sb.WriteString("# METADATA\n")

		// force order: `title`, `description`, `custom`
		if conveted.Title != "" {
			yml, err := yaml.Marshal(&rego.ConvertedLegacyAnnotations{Title: conveted.Title})
			if err != nil {
				logger.WithError(err).Error("cant convert annotations to yaml")
				continue
			}
			appendCommentedYaml(&sb, yml)
		}
		if conveted.Description != "" {
			yml, err := yaml.Marshal(&rego.ConvertedLegacyAnnotations{Description: conveted.Description})
			if err != nil {
				logger.WithError(err).Error("cant convert annotations to yaml")
				continue
			}
			appendCommentedYaml(&sb, yml)
		}
		if len(conveted.Custom) > 0 {
			yml, err := yaml.Marshal(&rego.ConvertedLegacyAnnotations{Custom: conveted.Custom})
			if err != nil {
				logger.WithError(err).Error("cant convert annotations to yaml")
				continue
			}
			appendCommentedYaml(&sb, yml)
		}

		sb.WriteString(r.LegacyConversionSource())
		sb.WriteByte('\n')

		if err := ioutil.WriteFile(r.Path(), []byte(sb.String()), 0644); err != nil {
			return fmt.Errorf("writing constraint: %w", err)
		}
	}

	// log.WithField("num_policies", len(violations)).Info("completed successfully")

	return nil
}

func appendCommentedYaml(sb *strings.Builder, yaml []byte) {
	split := strings.Split(string(yaml), "\n")

	for i, line := range split {
		// avoid trailing spaces
		if line == "" {
			// skip last line if it's empty
			if i != len(split)-1 {
				sb.WriteString("#\n")
			}
			continue
		}

		sb.WriteString("# ")
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
}
