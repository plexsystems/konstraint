package rego

import (
	"fmt"
	"regexp"

	"github.com/open-policy-agent/opa/ast"
)

func LoadPoliciesWithAction(filesContents map[string]string, action string) ([]RegoFile, error) {
	regoFiles, err := loadRegoFiles(filesContents)
	if err != nil {
		return nil, fmt.Errorf("load rego files: %w", err)
	}

	policies := getPoliciesWithAction(regoFiles, action)
	return policies, nil
}

func LoadPolicies(filesContents map[string]string) ([]RegoFile, error) {
	regoFiles, err := loadRegoFiles(filesContents)
	if err != nil {
		return nil, fmt.Errorf("load rego files: %w", err)
	}

	policies := getPolicies(regoFiles)
	return policies, nil
}

func LoadLibraries(filesContents map[string]string) ([]RegoFile, error) {
	regoFiles, err := loadRegoFiles(filesContents)
	if err != nil {
		return nil, fmt.Errorf("load rego files: %w", err)
	}

	libraries := getLibraries(regoFiles)
	return libraries, nil
}

func getPoliciesWithAction(regoFiles []RegoFile, action string) []RegoFile {
	var matchingPolicies []RegoFile
	for _, regoFile := range regoFiles {
		for _, ruleAction := range regoFile.RulesActions {
			if ruleAction == action {
				matchingPolicies = append(matchingPolicies, regoFile)
			}
		}
	}

	return matchingPolicies
}

func getPolicies(regoFiles []RegoFile) []RegoFile {
	var matchingPolicies []RegoFile
	for _, regoFile := range regoFiles {
		if len(regoFile.RulesActions) > 0 {
			matchingPolicies = append(matchingPolicies, regoFile)
		}
	}

	return matchingPolicies
}

func getLibraries(regoFiles []RegoFile) []RegoFile {
	var matchingPolicies []RegoFile
	for _, regoFile := range regoFiles {
		if len(regoFile.RulesActions) != 0 {
			matchingPolicies = append(matchingPolicies, regoFile)
		}
	}

	return matchingPolicies
}

func loadRegoFiles(filesContents map[string]string) ([]RegoFile, error) {
	var regoFiles []RegoFile
	for path, contents := range filesContents {
		regoFile, err := newRegoFile(path, contents)
		if err != nil {
			return nil, fmt.Errorf("new rego file: %w", err)
		}

		regoFiles = append(regoFiles, regoFile)
	}

	return regoFiles, nil
}

func newRegoFile(filePath string, contents string) (RegoFile, error) {
	module, err := ast.ParseModule(filePath, contents)
	if err != nil {
		return RegoFile{}, fmt.Errorf("parse module: %w", err)
	}

	var importPackages []string
	for i := range module.Imports {
		importPackages = append(importPackages, module.Imports[i].Path.String())
	}

	RegoFile := RegoFile{
		FilePath:       filePath,
		PackageName:    module.Package.Path.String(),
		ImportPackages: importPackages,
		Contents:       contents,
		RulesActions:   getModuleRulesActions(module.Rules),
	}

	return RegoFile, nil
}

func getModuleRulesActions(rules []*ast.Rule) []string {
	var rulesActions []string
	re := regexp.MustCompile("^\\s*([a-z]+)\\[")
	for _, rule := range rules {
		match := re.FindStringSubmatch(rule.Head.String())
		if len(match) == 0 {
			continue
		}
		rulesActions = append(rulesActions, match[1])
	}
	return rulesActions
}
