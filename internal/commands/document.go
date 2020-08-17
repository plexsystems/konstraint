package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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
}

// Document is a single policy document.
type Document struct {
	Header       Header
	Severities   []string
	HasViolation bool
	HasWarning   bool
	URL          string
	Rego         string
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
	cmd.Flags().String("url", "", "The URL where the policy files are hosted at (e.g. https://github.com/policies")

	return &cmd
}

func runDocCommand(path string) error {
	outputDirectory := filepath.Dir(viper.GetString("output"))
	docs, err := getDocumentation(path, outputDirectory)
	if err != nil {
		return fmt.Errorf("get documentation: %w", err)
	}

	t, err := template.New("docs").Parse(docTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	var templateBuffer bytes.Buffer
	w := bufio.NewWriter(&templateBuffer)
	if err := t.Execute(w, docs); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	if err := ioutil.WriteFile(viper.GetString("output"), templateBuffer.Bytes(), os.ModePerm); err != nil {
		return fmt.Errorf("writing documentation: %w", err)
	}

	return nil
}

func getDocumentation(path string, outputDirectory string) ([]Document, error) {
	policies, err := rego.GetFiles(path)
	if err != nil {
		return nil, fmt.Errorf("get files: %w", err)
	}

	var documents []Document
	for _, policy := range policies {
		header, err := getHeader(policy.Comments)
		if err != nil {
			return nil, fmt.Errorf("get header: %w", err)
		}

		if header.Title == "" {
			continue
		}

		var url string
		if viper.GetString("url") != "" {
			url = viper.GetString("url") + "/" + policy.FilePath
		} else {
			relPath, err := filepath.Rel(outputDirectory, policy.FilePath)
			if err != nil {
				return nil, fmt.Errorf("rel path: %w", err)
			}
			relDir := filepath.Dir(relPath)

			// Markdown specification notes that all pathing should be represented
			// with a forward slash.
			url = strings.ReplaceAll(relDir, string(os.PathSeparator), "/")
		}

		regoWithoutComments := getRegoWithoutComments(policy.Contents)
		document := Document{
			Header:     header,
			Severities: policy.RuleNames,
			URL:        trimContent(url),
			Rego:       trimContent(regoWithoutComments),
		}

		if contains(policy.RuleNames, "violation") {
			document.HasViolation = true
		}

		if contains(policy.RuleNames, "warn") {
			document.HasWarning = true
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

	anchor := strings.ReplaceAll(strings.ToLower(title), " ", "-")

	header := Header{
		Title:       trimContent(title),
		Description: trimContent(description),
		Resources:   trimContent(resources),
		Anchor:      trimContent(anchor),
	}

	return header, nil
}

func trimContent(content string) string {
	content = strings.Trim(content, " ")
	content = strings.Trim(content, "\n")
	return content
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
