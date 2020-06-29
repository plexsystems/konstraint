package commands

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewDocCommand creates a new doc command
func NewDocCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "doc <dir>",
		Short: "Generate documentation from Rego policies",

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

	cmd.Flags().StringP("output", "o", "policies.md", "output location (including filename) for the policy documentation")

	return &cmd
}

// PolicyCommentBlock represent a comment block in a rego file
type PolicyCommentBlock struct {
	APIGroups   []string
	Kinds       []string
	Description string
}

func runDocCommand(path string) error {
	policyDocumentation, err := getPolicyDocumentation(path)
	if err != nil {
		return fmt.Errorf("get policy documentation: %w", err)
	}

	err = ioutil.WriteFile(filepath.Join(path, viper.GetString("output")), []byte(policyDocumentation), os.ModePerm)
	if err != nil {
		return fmt.Errorf("writing documentation: %w", err)
	}

	return nil
}

func getPolicyDocumentation(path string) (string, error) {
	regoFilePaths, err := getRegoFilePaths(path)
	if err != nil {
		return "", fmt.Errorf("get rego files: %w", err)
	}

	var allPolicyCommentBlocks []PolicyCommentBlock
	for _, regoFilePath := range regoFilePaths {
		policyBytes, err := ioutil.ReadFile(regoFilePath)
		if err != nil {
			return "", fmt.Errorf("reading file: %w", err)
		}

		policyCommentBlocks, err := getPolicyCommentBlocks(policyBytes)
		if err != nil {
			return "", fmt.Errorf("get policy comment blocks: %w", err)
		}

		allPolicyCommentBlocks = append(allPolicyCommentBlocks, policyCommentBlocks...)
	}

	policyDocument := "# Policies\n\n"
	policyDocument += "|API Groups|Kinds|Description|\n"
	policyDocument += "|---|---|---|\n"

	for _, policyCommentBlock := range allPolicyCommentBlocks {
		apiGroups := strings.Join(policyCommentBlock.APIGroups, ", ")
		kinds := strings.Join(policyCommentBlock.Kinds, ", ")
		policyDocument += fmt.Sprintf("|%s|%s|%s|\n", apiGroups, kinds, policyCommentBlock.Description)
	}

	return policyDocument, nil
}

func getPolicyCommentBlocks(policy []byte) ([]PolicyCommentBlock, error) {
	byteReader := bytes.NewReader(policy)
	_, policyComments, errors := ast.NewParser().WithReader(byteReader).Parse()
	if len(errors) > 0 {
		return nil, fmt.Errorf("parsing rego: %w", errors)
	}

	var policyCommentBlocks []PolicyCommentBlock
	var description string
	for _, policyComment := range policyComments {
		commentText := string(policyComment.Text)
		if !strings.Contains(commentText, "@Kinds") {
			description = commentText
			continue
		}

		kindGroups := strings.Split(commentText, " ")
		kindGroups = kindGroups[2:]

		var apiGroups []string
		var kinds []string
		for _, kindGroup := range kindGroups {
			kindTokens := strings.Split(kindGroup, "/")

			apiGroups = append(apiGroups, kindTokens[0])
			kinds = append(kinds, kindTokens[1])
		}

		dedupedGroups := getDedupedGroups(apiGroups)

		policyCommentBlock := PolicyCommentBlock{
			APIGroups:   dedupedGroups,
			Kinds:       kinds,
			Description: strings.Trim(description, " "),
		}

		policyCommentBlocks = append(policyCommentBlocks, policyCommentBlock)
	}

	return policyCommentBlocks, nil
}

func getDedupedGroups(groups []string) []string {
	var dedupedGroups []string
	for _, group := range groups {
		if !contains(dedupedGroups, group) {
			dedupedGroups = append(dedupedGroups, group)
		}
	}

	return dedupedGroups
}

func contains(groups []string, group string) bool {
	for _, currentGroup := range groups {
		if strings.EqualFold(currentGroup, group) {
			return true
		}
	}

	return false
}
