package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/plexsystems/konstraint/internal/rego"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Header is the header comment block found on a Rego policy.
type Header struct {
	Title       string
	Description string
	Resources   string
}

// Document is a single policy document.
type Document struct {
	Header   Header
	Severity string
	URL      string
	Rego     string
}

func newDocCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "doc <dir>",
		Short: "Generate documentation from Rego policies",
		Example: `Generate the documentation
	konstraint doc

Save the documentation to a specific directory
	konstraint doc --output docs/policies.md`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("output", cmd.Flags().Lookup("output")); err != nil {
				return fmt.Errorf("bind output flag: %w", err)
			}

			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runDocCommand(path)
		},
	}

	cmd.Flags().StringP("output", "o", "policies.md", "Output location (including filename) for the policy documentation")

	return &cmd
}

func runDocCommand(path string) error {
	outputDirectory := filepath.Dir(viper.GetString("output"))
	violationDocs, err := getDocumentation(path, "violation", outputDirectory)
	if err != nil {
		return fmt.Errorf("get violation documentation: %w", err)
	}

	warningDocs, err := getDocumentation(path, "warn", outputDirectory)
	if err != nil {
		return fmt.Errorf("get warn documentation: %w", err)
	}

	documentContents := "# Policies"
	documentContents += "\n\n"

	// Table of contents (Violations)
	if len(violationDocs) > 0 {
		documentContents += "## Violations"
		documentContents += "\n\n"
		for _, document := range violationDocs {
			documentContents += "* [" + document.Header.Title + "](#" + strings.ReplaceAll(strings.ToLower(document.Header.Title), " ", "-") + ")"
			documentContents += "\n"
		}

		documentContents += "\n"
	}

	// Table of contents (Warnings)
	if len(warningDocs) > 0 {
		documentContents += "## Warnings"
		documentContents += "\n\n"
		for _, document := range warningDocs {
			documentContents += "* [" + document.Header.Title + "](#" + strings.ReplaceAll(strings.ToLower(document.Header.Title), " ", "-") + ")"
			documentContents += "\n"
		}

		documentContents += "\n"
	}

	for _, document := range violationDocs {
		documentContents += "## " + document.Header.Title
		documentContents += "\n\n"

		documentContents += "**Severity:** " + document.Severity
		documentContents += "\n\n"

		documentContents += "**Resources:** " + document.Header.Resources
		documentContents += "\n\n"

		documentContents += document.Header.Description
		documentContents += "\n"

		documentContents += "### Rego"
		documentContents += "\n\n"

		documentContents += "```rego"
		documentContents += "\n"

		documentContents += document.Rego
		documentContents += "\n"

		documentContents += "```"
		documentContents += "\n"

		documentContents += "_source: [" + document.URL + "](" + document.URL + ")_"
		documentContents += "\n\n"
	}

	for _, document := range warningDocs {
		documentContents += "## " + document.Header.Title
		documentContents += "\n\n"

		documentContents += "**Severity:** " + document.Severity
		documentContents += "\n\n"

		documentContents += "**Resources:** " + document.Header.Resources
		documentContents += "\n\n"

		documentContents += document.Header.Description
		documentContents += "\n"

		documentContents += "### Rego"
		documentContents += "\n\n"

		documentContents += "```rego"
		documentContents += "\n"

		documentContents += document.Rego
		documentContents += "\n"

		documentContents += "```"
		documentContents += "\n"

		documentContents += "_source: [" + document.URL + "](" + document.URL + ")_"
		documentContents += "\n\n"
	}

	documentContents = strings.TrimSuffix(documentContents, "\n")
	if err := ioutil.WriteFile(viper.GetString("output"), []byte(documentContents), os.ModePerm); err != nil {
		return fmt.Errorf("writing documentation: %w", err)
	}

	return nil
}

func getDocumentation(path string, severity string, outputDirectory string) ([]Document, error) {
	policies, err := rego.GetFilesWithRule(path, severity)
	if err != nil {
		return nil, fmt.Errorf("get files: %w", err)
	}

	var documents []Document
	for _, policy := range policies {
		header, err := getHeader(policy.Comments)
		if err != nil {
			return nil, fmt.Errorf("get header: %w", err)
		}

		relPath, err := filepath.Rel(outputDirectory, policy.FilePath)
		if err != nil {
			return nil, fmt.Errorf("rel path: %w", err)
		}
		relDir := filepath.Dir(relPath)

		regoWithoutComments := getRegoWithoutComments(policy.Contents)

		document := Document{
			Header:   header,
			Severity: severity,
			URL:      relDir,
			Rego:     regoWithoutComments,
		}

		documents = append(documents, document)
	}

	return documents, nil
}

func getHeader(comments []string) (Header, error) {
	var title string
	var description string
	var resources string
	for _, comment := range comments {
		if strings.Contains(comment, "@title") {
			title = strings.SplitAfter(comment, "@title")[1]
			title = strings.TrimPrefix(title, " ")
			continue
		}

		if strings.Contains(comment, "@kinds") {
			matchers := GetMatchersFromComments([]string{comment})
			for _, kindMatcher := range matchers.KindMatchers {
				resources += kindMatcher.APIGroup + "/" + kindMatcher.Kind + " "
			}
			break
		}

		comment = strings.TrimSpace(comment)
		description += comment + "\n"
	}

	description = strings.TrimSuffix(description, "\n")

	header := Header{
		Title:       strings.Trim(title, " "),
		Description: strings.Trim(description, " "),
		Resources:   strings.Trim(resources, " "),
	}

	return header, nil
}

func getRegoWithoutComments(rego string) string {
	var regoWithoutComments string
	lines := strings.Split(rego, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}

		regoWithoutComments += line + "\n"
	}

	regoWithoutComments = strings.TrimSuffix(regoWithoutComments, "\n")
	return regoWithoutComments
}

func contains(collection []string, item string) bool {
	for _, value := range collection {
		if strings.EqualFold(value, item) {
			return true
		}
	}

	return false
}
