package rego

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

type Rego struct {
	path      string
	contents  string
	libraries []string
	module    *ast.Module
}

func Parse(path string) (Rego, error) {
	contents, err := getContents(path)
	if err != nil {
		return Rego{}, fmt.Errorf("get contents: %w", err)
	}

	module, err := ast.ParseModule(path, contents)
	if err != nil {
		return Rego{}, fmt.Errorf("parse module: %w", err)
	}

	allLibraries, err := getLibraries(path, module)
	if err != nil {
		return Rego{}, fmt.Errorf("get libraries: %w", err)
	}

	libraries := getRecursiveImports(module, allLibraries)

	rego := Rego{
		path:      path,
		contents:  contents,
		module:    module,
		libraries: libraries,
	}

	return rego, nil
}

func (r Rego) Severity() string {
	rules := []string{"violation", "warn", "deny"}

	var severity string
	for i := range r.module.Rules {
		currentRule := r.module.Rules[i].Head.Name.String()
		if !contains(rules, currentRule) {
			continue
		}

		severity = currentRule

		if severity == "deny" {
			severity = "violation"
		}

		if severity == "warn" {
			severity = "warning"
		}

		break
	}

	return strings.Title(severity)
}

func GetAll(directory string) ([]Rego, error) {
	filePaths, err := getFilePaths(directory)
	if err != nil {
		return nil, fmt.Errorf("get file paths: %w", err)
	}

	var violations []Rego
	for _, filePath := range filePaths {
		rego, err := Parse(filePath)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}

		if rego.Severity() == "" {
			continue
		}

		violations = append(violations, rego)
	}

	return violations, nil
}

func GetViolations(directory string) ([]Rego, error) {
	files, err := GetAll(directory)
	if err != nil {
		return nil, fmt.Errorf("get all: %w", err)
	}

	var violations []Rego
	for _, file := range files {
		if file.Severity() != "violation" {
			continue
		}

		violations = append(violations, file)
	}

	return violations, nil
}

func (r Rego) Kind() string {
	kind := filepath.Base(filepath.Dir(r.path))
	kind = strings.ReplaceAll(kind, "-", " ")
	kind = strings.Title(kind)
	kind = strings.ReplaceAll(kind, " ", "")

	return kind
}

func (r Rego) Name() string {
	return strings.ToLower(r.Kind())
}

func (r Rego) Path() string {
	return r.path
}

func (r Rego) Title() string {
	var title string
	for c := range r.module.Comments {
		if !strings.Contains(r.module.Comments[c].String(), "@title") {
			continue
		}

		title = strings.SplitAfter(r.module.Comments[c].String(), "@title")[1]
		break
	}

	return trimContent(title)
}

func (r Rego) Description() string {
	var description string
	for c := range r.module.Comments {
		comment := strings.TrimSpace(string(r.module.Comments[c].Text))
		if strings.Contains(comment, "@") {
			continue
		}

		description += comment
		description += "\n"
	}

	return trimContent(description)
}

func (r Rego) Source() string {
	var regoWithoutComments string
	lines := strings.Split(r.contents, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}

		regoWithoutComments += line + "\n"
	}

	return trimContent(regoWithoutComments)
}

func (r Rego) Libraries() []string {
	return r.libraries
}

func getLibraries(path string, module *ast.Module) (map[string]*ast.Module, error) {
	if len(module.Imports) == 0 {
		return make(map[string]*ast.Module), nil
	}

	libraryDir, err := findLibraryDir(path)
	if err != nil {
		return nil, fmt.Errorf("find library dir: %w", err)
	}

	libraryFilePaths, err := getFilePaths(libraryDir)
	if err != nil {
		return nil, fmt.Errorf("get file paths: %w", err)
	}

	libraries := make(map[string]*ast.Module)
	for _, libraryFilePath := range libraryFilePaths {
		contents, err := getContents(libraryFilePath)
		if err != nil {
			return nil, fmt.Errorf("get contents: %w", err)
		}

		libraryModule, err := ast.ParseModule(libraryFilePath, contents)
		if err != nil {
			return nil, fmt.Errorf("parse module: %w", err)
		}

		libraries[libraryModule.Package.Path.String()] = libraryModule
	}

	return libraries, nil
}

func findLibraryDir(path string) (string, error) {
	allowedLibraryDirectories := []string{"lib", "libs", "util", "utils"}

	currentDirectory := filepath.Dir(path)
	files, err := ioutil.ReadDir(currentDirectory)
	if err != nil {
		return "", fmt.Errorf("read directory: %w", err)
	}

	for i := range files {
		if files[i].IsDir() && contains(allowedLibraryDirectories, files[i].Name()) {
			return filepath.Join(currentDirectory, files[i].Name()), nil
		}
	}

	return findLibraryDir(filepath.Dir(path))
}

func getRecursiveImports(module *ast.Module, imports map[string]*ast.Module) []string {
	var recursiveImports []string
	var nestedImports []*ast.Module
	for i := range module.Imports {
		importModule := imports[module.Imports[i].Path.String()]
		recursiveImports = append(recursiveImports, importModule.String())

		if len(importModule.Imports) > 0 {
			nestedImports = append(nestedImports, importModule)
		}
	}

	for i := range nestedImports {
		return append(recursiveImports, getRecursiveImports(nestedImports[i], imports)...)
	}

	return []string{}
}

func getContents(path string) (string, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	// Many YAML parsers do not like rendering out CRLF when writing the YAML to disk.
	// This causes ConstraintTemplates to be rendered with the line breaks as text,
	// rather than the actual line break.
	return strings.ReplaceAll(string(contents), "\r", ""), nil

}

func getFilePaths(path string) ([]string, error) {
	var filePaths []string
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

		filePaths = append(filePaths, currentFilePath)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return filePaths, nil
}

func contains(collection []string, item string) bool {
	for _, value := range collection {
		if strings.EqualFold(value, item) {
			return true
		}
	}

	return false
}

func trimContent(content string) string {
	content = strings.TrimSpace(content)
	content = strings.Trim(content, "\n")
	return content
}
