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

// Header represents the top comment in a Rego file
type Header struct {
	Title       string
	Description string
	APIGroups   []string
	Kinds       []string
}

type Document struct {
	Header    Header
	RegoLines []string
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
		documentContents += "# " + document.Header.Title + "\n"

		// Description
		documentContents += document.Header.Description + "\n"

		// API Groups
		documentContents += "API Groups: "
		for _, group := range document.Header.APIGroups {
			documentContents += group + " "
		}
		documentContents += "\n"

		// Kinds
		documentContents += "Kinds: "
		for _, kind := range document.Header.Kinds {
			documentContents += kind + " "
		}
		documentContents += "\n"
		documentContents += "\n"

		// Rego
		documentContents += "```rego" + "\n"
		for _, regoLine := range document.RegoLines {
			documentContents += regoLine + "\n"
		}
		documentContents += "```"

		// Ship it
		if err := ioutil.WriteFile(viper.GetString("output"), []byte(documentContents), os.ModePerm); err != nil {
			return fmt.Errorf("writing documentation: %w", err)
		}
	}

	return nil
}

func getDocumentation(path string, outputDirectory string) ([]Document, error) {
	regoFilePaths, err := getRegoFilePaths(path)
	if err != nil {
		return nil, fmt.Errorf("get rego files: %w", err)
	}

	policies, err := rego.LoadPolicies(regoFilePaths)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	var documents []Document
	for _, policy := range policies {
		header, err := getHeader(policy.Comments)
		if err != nil {
			return nil, fmt.Errorf("get policy comment blocks: %w", err)
		}

		regoWithoutComments := getRegoWithoutComments(policy.Contents)
		document := Document{
			Header:    header,
			RegoLines: regoWithoutComments,
		}

		documents = append(documents, document)
	}

	return documents, nil
}

func getHeader(comments []string) (Header, error) {
	var title string
	var description string
	var apiGroups []string
	var kinds []string
	for _, comment := range comments {
		if strings.Contains(comment, "@title") {
			title = strings.SplitAfter(comment, "@title")[1]
			continue
		}

		if strings.Contains(comment, "@kinds") {
			kindGroups := strings.Split(comment, " ")[2:]
			for _, kindGroup := range kindGroups {
				kindTokens := strings.Split(kindGroup, "/")
				if !contains(apiGroups, kindTokens[0]) {
					apiGroups = append(apiGroups, kindTokens[0])
				}

				kinds = append(kinds, kindTokens[1])
			}
			break
		}

		comment = strings.TrimSpace(comment)
		description = description + comment + "\n"
	}

	header := Header{
		Title:       strings.Trim(title, " "),
		Description: strings.Trim(description, " "),
		APIGroups:   apiGroups,
		Kinds:       kinds,
	}

	return header, nil
}

func getRegoWithoutComments(rego string) []string {
	var regoWithoutComments []string
	lines := strings.Split(rego, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}

		regoWithoutComments = append(regoWithoutComments, line)
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

func getNameFromPath(path string) string {
	name := filepath.Base(filepath.Dir(path))
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.Title(name)

	return name
}
