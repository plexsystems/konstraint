package rego

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

// GetFilesWithRule gets all Rego files in the given path and its subdirectories that contain the specified rule.
func GetFilesWithRule(path string, rule string) ([]File, error) {
	allFiles, err := GetFiles(path)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	filesWithRule := getFilesWithRule(allFiles, rule)
	return filesWithRule, nil
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

	var ruleNames []string
	for _, rule := range module.Rules {
		ruleNames = append(ruleNames, rule.Head.Name.String())
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

func getFilesWithRule(regoFiles []File, rule string) []File {
	var matchingPolicies []File
	for _, policy := range regoFiles {
		for _, ruleName := range policy.RuleNames {
			if ruleName == rule {
				matchingPolicies = append(matchingPolicies, policy)
			}
		}
	}

	return matchingPolicies
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

func readFilesContents(filePaths []string) (map[string]string, error) {
	filesContents := make(map[string]string)
	for _, filePath := range filePaths {
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}

		// Many YAML parsers do not like rendering out CRLF when writing the YAML to disk.
		// This causes ConstraintTemplates to be rendered with the line breaks as text,
		// rather than the actual line break.
		filesContents[filePath] = strings.ReplaceAll(string(data), "\r", "")
	}

	return filesContents, nil
}
