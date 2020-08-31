package rego

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

// Rego represents a parsed rego file.
type Rego struct {
	path      string
	contents  string
	module    *ast.Module
	libraries []string
}

// Parse parses a rego file at the given path.
func Parse(path string) (Rego, error) {
	contents, err := getContents(path)
	if err != nil {
		return Rego{}, fmt.Errorf("get contents: %w", err)
	}

	module, err := ast.ParseModule(path, contents)
	if err != nil {
		return Rego{}, fmt.Errorf("parse module: %w", err)
	}

	for c := range module.Comments {
		module.Comments[c].Text = bytes.TrimSpace(module.Comments[c].Text)
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

// Severity returns the severity of the rego file.
func (r Rego) Severity() string {
	rules := []string{"violation", "warn", "deny"}

	var severity string
	for i := range r.module.Rules {
		severity = r.module.Rules[i].Head.Name.String()
		if !contains(rules, severity) {
			continue
		}

		if severity == "warn" {
			severity = "warning"
		}

		break
	}

	return strings.Title(severity)
}

// GetAll gets all of the rego files found in the given directory as well as any subdirectories.
// Only rego files that contain a valid severity will be returned.
func GetAll(directory string) ([]Rego, error) {
	filePaths, err := getFilePaths(directory)
	if err != nil {
		return nil, fmt.Errorf("get file paths: %w", err)
	}

	var files []Rego
	for _, filePath := range filePaths {
		rego, err := Parse(filePath)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}

		if rego.Severity() == "" {
			continue
		}

		files = append(files, rego)
	}

	return files, nil
}

// GetViolations gets all of the files found in the given directory as well as any subdirectories
// that have a violation severity.
func GetViolations(directory string) ([]Rego, error) {
	files, err := GetAll(directory)
	if err != nil {
		return nil, fmt.Errorf("get all: %w", err)
	}

	var violations []Rego
	for _, file := range files {
		if file.Severity() != "Violation" {
			continue
		}

		violations = append(violations, file)
	}

	return violations, nil
}

// Kind returns the Kubernetes Kind of the rego file.
// The kind of the rego file is determined by the name of the directory
// that the rego file exists in.
func (r Rego) Kind() string {
	kind := filepath.Base(filepath.Dir(r.path))
	kind = strings.ReplaceAll(kind, "-", " ")
	kind = strings.Title(kind)
	kind = strings.ReplaceAll(kind, " ", "")

	return kind
}

// Name returns the name of the rego file.
// The name of the rego file is its kind as lowercase.
func (r Rego) Name() string {
	return strings.ToLower(r.Kind())
}

// Path returns the original file path of the rego file.
func (r Rego) Path() string {
	return r.path
}

// Title returns the title found in the header comment of the rego file.
// The @title token can be used to set the title of the rego file.
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

// Description returns the entire description found in the header comment of the rego file.
func (r Rego) Description() string {
	var description string
	for c := range r.module.Comments {
		comment := strings.TrimSpace(string(r.module.Comments[c].Text))

		// The @kinds token is the last line of the header block.
		// When this token appears, we consider this point to be the end of the description.
		if strings.Contains(comment, "@kinds") {
			break
		}

		if strings.Contains(comment, "@") {
			continue
		}

		description += comment
		description += "\n"
	}

	return trimContent(description)
}

// Source returns the original source code inside of the rego file, minus any comments.
func (r Rego) Source() string {
	var regoWithoutComments string
	lines := strings.Split(r.contents, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}

		regoWithoutComments += line + "\n"
	}

	regoWithoutComments = strings.TrimSuffix(regoWithoutComments, "\n")
	return regoWithoutComments
}

// Libraries returns all of the contents for the libraries that this file imports.
// This operation is performed recursively to include the contents of each imports import.
func (r Rego) Libraries() []string {
	return r.libraries
}

// getLibraries will get all of the libraries and store them into a map that is keyed
// by the name of the package.
//
// This enables us to take any given import found inside of a Rego file and find
// the associated module.
func getLibraries(path string, module *ast.Module) (map[string]Rego, error) {
	if len(module.Imports) == 0 {
		return map[string]Rego{}, nil
	}

	currentDirectory := filepath.Dir(path)
	libraryDir, err := findLibraryDir(currentDirectory)
	if err != nil {
		return nil, fmt.Errorf("find library dir: %w", err)
	}

	libraryFilePaths, err := getFilePaths(libraryDir)
	if err != nil {
		return nil, fmt.Errorf("get file paths: %w", err)
	}

	libraries := make(map[string]Rego)
	for _, libraryFilePath := range libraryFilePaths {
		contents, err := getContents(libraryFilePath)
		if err != nil {
			return nil, fmt.Errorf("get contents: %w", err)
		}

		libraryModule, err := ast.ParseModule(libraryFilePath, contents)
		if err != nil {
			return nil, fmt.Errorf("parse module: %w", err)
		}

		rego := Rego{
			contents: contents,
			module:   libraryModule,
		}

		libraries[libraryModule.Package.Path.String()] = rego
	}

	return libraries, nil
}

func findLibraryDir(directory string) (string, error) {
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		return "", fmt.Errorf("read directory: %w", err)
	}

	for i := range files {
		if !files[i].IsDir() {
			continue
		}

		if !contains([]string{"lib", "libs", "util", "utils"}, files[i].Name()) {
			continue
		}

		return filepath.Join(directory, files[i].Name()), nil
	}

	// In the event that a library directory was not found in the current directory, we
	// recursively call the method, going up a directory each time until it is found.
	return findLibraryDir(filepath.Dir(directory))
}

func getRecursiveImports(module *ast.Module, imports map[string]Rego) []string {
	var recursiveImports []string
	for i := range module.Imports {
		imported := imports[module.Imports[i].Path.String()]
		recursiveImports = append(recursiveImports, imported.Source())
	}

	for i := range module.Imports {
		imported := imports[module.Imports[i].Path.String()]
		return append(recursiveImports, getRecursiveImports(imported.module, imports)...)
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
