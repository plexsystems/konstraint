package rego

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/open-policy-agent/opa/ast"
)

// LoadPoliciesWithAction loads all policies from rego with rules with a given action name
func LoadPoliciesWithAction(files []string, action string) ([]File, error) {
	regoFiles, err := loadRegoFiles(files)
	if err != nil {
		return nil, fmt.Errorf("load rego files: %w", err)
	}

	policies := getPoliciesWithAction(regoFiles, action)
	return policies, nil
}

// LoadPolicies loads all policies from rego with rules
func LoadPolicies(files []string) ([]File, error) {
	regoFiles, err := loadRegoFiles(files)
	if err != nil {
		return nil, fmt.Errorf("load rego files: %w", err)
	}

	policies := getPolicies(regoFiles)
	return policies, nil
}

// LoadLibraries loads all libraries from rego
func LoadLibraries(files []string) ([]File, error) {
	regoFiles, err := loadRegoFiles(files)
	if err != nil {
		return nil, fmt.Errorf("load rego files: %w", err)
	}

	return regoFiles, nil
}

// NewRegoFile parses the rego and creates a File
func NewRegoFile(filePath string, contents string) (File, error) {
	module, err := ast.ParseModule(filePath, contents)
	if err != nil {
		return File{}, fmt.Errorf("parse module: %w", err)
	}

	var importPackages []string
	for i := range module.Imports {
		importPackages = append(importPackages, module.Imports[i].Path.String())
	}

	file := File{
		FilePath:       filePath,
		PackageName:    module.Package.Path.String(),
		ImportPackages: importPackages,
		Contents:       contents,
		RulesActions:   getModuleRulesActions(module),
		Comments:       getModuleComments(module),
	}

	return file, nil
}

func getPoliciesWithAction(regoFiles []File, action string) []File {
	var matchingPolicies []File
	allPolicies := getPolicies(regoFiles)
	for _, policy := range allPolicies {
		for _, ruleAction := range policy.RulesActions {
			if ruleAction == action {
				matchingPolicies = append(matchingPolicies, policy)
			}
		}
	}

	return matchingPolicies
}

func getPolicies(regoFiles []File) []File {
	var policies []File
	for _, regoFile := range regoFiles {
		if len(regoFile.RulesActions) > 0 {
			policies = append(policies, regoFile)
		}
	}

	return policies
}

func loadRegoFiles(files []string) ([]File, error) {
	filesContents, err := readFilesContents(files)
	if err != nil {
		return nil, fmt.Errorf("read files: %w", err)
	}

	var regoFiles []File
	for path, contents := range filesContents {
		regoFile, err := NewRegoFile(path, contents)
		if err != nil {
			return nil, fmt.Errorf("new rego file: %w", err)
		}

		regoFiles = append(regoFiles, regoFile)
	}

	return regoFiles, nil
}

func getModuleRulesActions(module *ast.Module) []string {
	var rulesActions []string
	re := regexp.MustCompile("^\\s*([a-z]+)\\s*\\[\\s*msg")
	for _, rule := range module.Rules {
		match := re.FindStringSubmatch(rule.Head.String())
		if len(match) == 0 {
			continue
		}
		rulesActions = append(rulesActions, match[1])
	}
	return rulesActions
}

func getModuleComments(module *ast.Module) []string {
	var comments []string
	for _, comment := range module.Comments {
		comments = append(comments, string(comment.Text))
	}
	return comments
}

func readFilesContents(filePaths []string) (map[string]string, error) {
	filesContents := make(map[string]string)
	for _, filePath := range filePaths {
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}

		filesContents[filePath] = string(data)
	}

	return filesContents, nil
}
