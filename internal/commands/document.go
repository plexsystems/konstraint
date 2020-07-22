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

// PolicyCommentBlock represents a comment block in a rego file
type PolicyCommentBlock struct {
	APIGroups   []string
	Kinds       []string
	Description string
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
	policyDocumentation, err := getPolicyDocumentation(path, outputDirectory)
	if err != nil {
		return fmt.Errorf("get policy documentation: %w", err)
	}

	if err := ioutil.WriteFile(viper.GetString("output"), []byte(policyDocumentation), os.ModePerm); err != nil {
		return fmt.Errorf("writing documentation: %w", err)
	}

	return nil
}

func getPolicyDocumentation(path string, outputDirectory string) (string, error) {
	regoFilePaths, err := getRegoFilePaths(path)
	if err != nil {
		return "", fmt.Errorf("get rego files: %w", err)
	}

	policies, err := rego.LoadPolicies(regoFilePaths)
	if err != nil {
		return "", fmt.Errorf("load policies: %w", err)
	}

	policyDocument := "# Policies\n\n"
	policyDocument += "|Name|Rule Types|API Groups|Kinds|Description|\n"
	policyDocument += "|---|---|---|---|---|\n"

	for _, policy := range policies {
		policyCommentBlocks, err := getPolicyCommentBlocks(policy.Comments)
		if err != nil {
			return "", fmt.Errorf("get policy comment blocks: %w", err)
		}

		for _, policyCommentBlock := range policyCommentBlocks {
			relPath, err := filepath.Rel(outputDirectory, policy.FilePath)
			if err != nil {
				return "", fmt.Errorf("rel path: %w", err)
			}

			relDir := filepath.Dir(relPath)
			ruleTypes := strings.Join(policy.RulesActions, ", ")
			apiGroups := strings.Join(policyCommentBlock.APIGroups, ", ")
			kinds := strings.Join(policyCommentBlock.Kinds, ", ")

			policyDocument += fmt.Sprintf("|[%s](%s)|%s|%s|%s|%s|\n",
				getNameFromPath(policy.FilePath),
				relDir,
				ruleTypes,
				apiGroups,
				kinds,
				policyCommentBlock.Description,
			)
		}
	}

	return policyDocument, nil
}

func getPolicyCommentBlocks(comments []string) ([]PolicyCommentBlock, error) {
	var policyCommentBlocks []PolicyCommentBlock
	var description string
	for _, comment := range comments {
		if !strings.Contains(comment, "@Kinds") {
			description = comment
			continue
		}

		kindGroups := strings.Split(comment, " ")[2:]

		var apiGroups []string
		var kinds []string
		for _, kindGroup := range kindGroups {
			kindTokens := strings.Split(kindGroup, "/")

			if !contains(apiGroups, kindTokens[0]) {
				apiGroups = append(apiGroups, kindTokens[0])
			}

			kinds = append(kinds, kindTokens[1])
		}

		policyCommentBlock := PolicyCommentBlock{
			APIGroups:   apiGroups,
			Kinds:       kinds,
			Description: strings.Trim(description, " "),
		}

		policyCommentBlocks = append(policyCommentBlocks, policyCommentBlock)
	}

	return policyCommentBlocks, nil
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
