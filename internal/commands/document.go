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

// Matchers are the matchers that are applied to constraints.
type Matchers struct {
	APIGroups []string
	Kinds     []string
}

// Header is the header comment block found on a Rego policy.
type Header struct {
	Title       string
	Description string
	Resources   string
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
	documentation, err := getDocumentation(path, outputDirectory)
	if err != nil {
		return fmt.Errorf("get policy documentation: %w", err)
	}

	var documentContents string
	for _, document := range documentation {
		// Title
		documentContents += "# " + document.Header.Title
		documentContents += "\n"

		// Description
		documentContents += document.Header.Description
		documentContents += "\n"

		// API Groups
		documentContents += "Resources: " + document.Header.Resources
		documentContents += "\n"

		// Rego
		documentContents += "```rego"
		documentContents += document.Rego
		documentContents += "```"

		documentContents += "\n"

		// Ship it
		if err := ioutil.WriteFile(viper.GetString("output"), []byte(documentContents), os.ModePerm); err != nil {
			return fmt.Errorf("writing documentation: %w", err)
		}
	}

	return nil
}

func getDocumentation(path string, outputDirectory string) ([]Document, error) {
	policies, err := rego.GetFilesWithAction(path, "violation")
	if err != nil {
		return nil, fmt.Errorf("get files: %w", err)
	}

	var documents []Document
	for _, policy := range policies {
		header, err := getHeader(policy.Comments)
		if err != nil {
			return nil, fmt.Errorf("get policy comment blocks: %w", err)
		}

		relPath, err := filepath.Rel(outputDirectory, policy.FilePath)
		if err != nil {
			return nil, fmt.Errorf("rel path: %w", err)
		}
		relDir := filepath.Dir(relPath)

		regoWithoutComments := getRegoWithoutComments(policy.Contents)

		document := Document{
			Header: header,
			URL:    relDir,
			Rego:   regoWithoutComments,
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
			continue
		}

		if strings.Contains(comment, "@kinds") {
			resourceList := strings.Split(comment, " ")[2:]
			resources = strings.Join(resourceList, " ")
			resources += "\n"
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

		regoWithoutComments += "\n" + line
	}

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
