package rego

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

// File is a parsed Rego file.
type File struct {
	FilePath       string
	PackageName    string
	ImportPackages []string
	Contents       string
	RuleNames      []string
	Comments       []string
}

// GetFiles gets all Rego files in the given path and its subdirectories.
func GetFiles(path string) ([]File, error) {
	filePaths, err := getFilePaths(path)
	if err != nil {
		return nil, fmt.Errorf("load files: %w", err)
	}

	files, err := getFiles(filePaths)
	if err != nil {
		return nil, fmt.Errorf("load files: %w", err)
	}

	return files, nil
}

// GetFilesWithAction gets all Rego files in the given path and its subdirectories that contain the specified action.
func GetFilesWithAction(path string, action string) ([]File, error) {
	allFiles, err := GetFiles(path)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	filesWithAction := getFilesWithAction(allFiles, action)
	return filesWithAction, nil
}

// NewFile parses the rego and creates a File
func NewFile(filePath string, contents string) (File, error) {
	module, err := ast.ParseModule(filePath, contents)
	if err != nil {
		return File{}, fmt.Errorf("parse module: %w", err)
	}

	var importPackages []string
	for i := range module.Imports {
		importPackages = append(importPackages, module.Imports[i].Path.String())
	}

	ruleNames, err := getModuleRuleNames(module)
	if err != nil {
		return File{}, fmt.Errorf("get module rules: %w", err)
	}

	var comments []string
	for _, comment := range module.Comments {
		comments = append(comments, string(comment.Text))
	}

	file := File{
		FilePath:       filePath,
		PackageName:    module.Package.Path.String(),
		ImportPackages: importPackages,
		Contents:       contents,
		RuleNames:      ruleNames,
		Comments:       comments,
	}

	return file, nil
}

func getFilePaths(path string) ([]string, error) {
	var regoFilePaths []string
	err := filepath.Walk(path, func(currentFilePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk path: %w", err)
		}

		if fileInfo.IsDir() && fileInfo.Name() == ".git" {
			return filepath.SkipDir
		}

		if filepath.Ext(currentFilePath) != ".rego" || strings.HasSuffix(fileInfo.Name(), "_test.rego") {
			return nil
		}

		regoFilePaths = append(regoFilePaths, currentFilePath)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return regoFilePaths, nil
}

func getFilesWithAction(regoFiles []File, action string) []File {
	var matchingPolicies []File
	allPolicies := getPolicies(regoFiles)
	for _, policy := range allPolicies {
		for _, ruleAction := range policy.RuleNames {
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
		if len(regoFile.RuleNames) > 0 {
			policies = append(policies, regoFile)
		}
	}

	return policies
}

func getFiles(files []string) ([]File, error) {
	filesContents, err := readFilesContents(files)
	if err != nil {
		return nil, fmt.Errorf("read files: %w", err)
	}

	var regoFiles []File
	for path, contents := range filesContents {
		regoFile, err := NewFile(path, contents)
		if err != nil {
			return nil, fmt.Errorf("new rego file: %w", err)
		}

		regoFiles = append(regoFiles, regoFile)
	}

	sort.Slice(regoFiles, func(i, j int) bool {
		return regoFiles[i].FilePath < regoFiles[j].FilePath
	})

	return regoFiles, nil
}

func getModuleRuleNames(module *ast.Module) ([]string, error) {
	re, err := regexp.Compile(`^\s*([a-z]+)\s*\[\s*msg`)
	if err != nil {
		return nil, fmt.Errorf("compile regex: %w", err)
	}

	var rulesActions []string
	for _, rule := range module.Rules {
		match := re.FindStringSubmatch(rule.Head.String())
		if len(match) == 0 {
			continue
		}
		if contains(rulesActions, match[1]) {
			continue
		}
		rulesActions = append(rulesActions, match[1])
	}

	return rulesActions, nil
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

func contains(collection []string, item string) bool {
	for _, value := range collection {
		if strings.EqualFold(value, item) {
			return true
		}
	}

	return false
}
