package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/plexsystems/konstraint/internal/rego"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Header is the header comment block found on a Rego policy.
type Header struct {
	Title       string
	Description string
	Resources   string
	Anchor      string
	Parameters  []rego.Parameter
}

// Document is a single policy document.
type Document struct {
	Header Header
	URL    string
	Rego   string
}

func newDocCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "doc <dir>",
		Short: "Generate documentation from Rego policies",
		Example: `Generate the documentation
	konstraint doc

Save the documentation to a specific directory
	konstraint doc --output docs/policies.md
	
Set the URL where the policies are hosted at
	konstraint doc --url https://github.com/plexsystems/konstraint`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("output", cmd.Flags().Lookup("output")); err != nil {
				return fmt.Errorf("bind output flag: %w", err)
			}

			if err := viper.BindPFlag("url", cmd.Flags().Lookup("url")); err != nil {
				return fmt.Errorf("bind url flag: %w", err)
			}

			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runDocCommand(path)
		},
	}

	cmd.Flags().StringP("output", "o", "policies.md", "Output location (including filename) for the policy documentation")
	cmd.Flags().String("url", "", "The URL where the policy files are hosted at (e.g. https://github.com/policies)")

	return &cmd
}

func runDocCommand(path string) error {
	outputDirectory := filepath.Dir(viper.GetString("output"))
	if err := os.MkdirAll(outputDirectory, os.ModePerm); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	docs, err := getDocumentation(path, outputDirectory)
	if err != nil {
		return fmt.Errorf("get documentation: %w", err)
	}

	t, err := template.New("docs").Parse(docTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	f, err := os.OpenFile(viper.GetString("output"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return fmt.Errorf("opening file for writing: %w", err)
	}

	if err := t.Execute(f, docs); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return nil
}

func getDocumentation(path string, outputDirectory string) (map[rego.Severity][]Document, error) {
	policies, err := rego.GetAllSeverities(path)
	if err != nil {
		return nil, fmt.Errorf("get all severities: %w", err)
	}

	documents := make(map[rego.Severity][]Document)
	for _, policy := range policies {
		if policy.Title() == "" {
			continue
		}

		var url string
		if viper.GetString("url") != "" {
			url = viper.GetString("url") + "/" + policy.Path()
		} else {
			relPath, err := filepath.Rel(outputDirectory, policy.Path())
			if err != nil {
				return nil, fmt.Errorf("rel path: %w", err)
			}
			relDir := filepath.Dir(relPath)

			// Markdown specification notes that all pathing should be represented
			// with a forward slash.
			url = strings.ReplaceAll(relDir, string(os.PathSeparator), "/")
		}

		documentTitle := policy.Title()
		if policy.PolicyID() != "" {
			documentTitle = fmt.Sprintf("%s: %s", policy.PolicyID(), documentTitle)
		}

		anchor := strings.ToLower(strings.ReplaceAll(documentTitle, " ", "-"))
		anchor = strings.ReplaceAll(anchor, ":", "")

		matchers := policy.Matchers().String()
		if matchers == "" {
			matchers = "Any Resource"
		}

		header := Header{
			Title:       documentTitle,
			Description: policy.Description(),
			Resources:   matchers,
			Anchor:      anchor,
			Parameters:  policy.Parameters(),
		}

		document := Document{
			Header: header,
			URL:    url,
			Rego:   policy.Source(),
		}

		if policy.Severity() == "" {
			documents["Other"] = append(documents["Other"], document)
		} else if policy.Enforcement() == "dryrun" {
			documents["Not Enforced"] = append(documents["Not Enforced"], document)
		} else {
			documents[policy.Severity()] = append(documents[policy.Severity()], document)
		}
	}

	sortPoliciesByTitle(documents)
	return documents, nil
}

func sortPoliciesByTitle(policyMap map[rego.Severity][]Document) {
	for _, documents := range policyMap {
		sort.Slice(documents, func(i, j int) bool {
			return documents[i].Header.Title < documents[j].Header.Title
		})
	}
}
