package rego

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/loader"
)

// Severity describes the severity level of the rego file.
type Severity string

// The defined severity levels represent the valid severity
// levels that a rego file can have.
const (
	Violation Severity = "Violation"
	Warning   Severity = "Warning"
)

// Rego represents a parsed rego file.
type Rego struct {
	path         string
	raw          string
	comments     []string
	rules        []string
	dependencies []string
}

// GetAllSeverities gets all of the rego files found in the given
// directory as well as any subdirectories.
// Only rego files that contain a valid severity will be returned.
func GetAllSeverities(directory string) ([]Rego, error) {
	regos, err := parseDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("parse directory: %w", err)
	}

	var allSeverities []Rego
	for _, rego := range regos {
		if rego.Severity() == "" {
			continue
		}

		allSeverities = append(allSeverities, rego)
	}

	return allSeverities, nil
}

// GetViolations gets all of the files found in the given
// directory as well as any subdirectories.
// Only rego files that have a severity of violation will be returned.
func GetViolations(directory string) ([]Rego, error) {
	regos, err := parseDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("parse directory: %w", err)
	}

	var violations []Rego
	for _, rego := range regos {
		if rego.Severity() != Violation {
			continue
		}

		violations = append(violations, rego)
	}

	return violations, nil
}

// Path returns the original path of the rego file.
func (r Rego) Path() string {
	return r.path
}

// Severity returns the severity of the rego file.
// When a rego file has multiple rules that are considered
// to be different severities, the first rule is chosen.
func (r Rego) Severity() Severity {
	var severity Severity
	for _, rule := range r.rules {
		if rule == "violation" {
			severity = Violation
			break
		}

		if rule == "warn" {
			severity = Warning
			break
		}
	}

	return severity
}

// Kind returns the Kubernetes Kind of the rego file.
// The kind of the rego file is determined by the
// name of the directory that the rego file exists in.
func (r Rego) Kind() string {
	kind := filepath.Base(filepath.Dir(r.Path()))
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

// Title returns the title found in the header comment of the rego file.
func (r Rego) Title() string {
	var title string
	for _, comment := range r.comments {
		if !strings.Contains(comment, "@title") {
			continue
		}

		title = strings.SplitAfter(comment, "@title")[1]
		break
	}

	return trimString(title)
}

// Description returns the entire description
// found in the header comment of the rego file.
func (r Rego) Description() string {
	var description string
	for _, comment := range r.comments {

		// When the  token appears, we consider this point to
		// be the end of the description.
		if strings.HasPrefix(comment, "@kinds") {
			break
		}

		if strings.HasPrefix(comment, "@") {
			continue
		}

		description += comment
		description += "\n"
	}

	return trimString(description)
}

// Source returns the original source code inside
// of the rego file without any comments.
func (r Rego) Source() string {
	return removeComments(r.raw)
}

// Dependencies returns all of the source for the rego files that this
// rego file depends on.
func (r Rego) Dependencies() []string {
	return r.dependencies
}

func parseDirectory(directory string) ([]Rego, error) {

	// Recursively find all rego files (ignoring test files), starting at the given directory.
	result, err := loader.NewFileLoader().Filtered([]string{directory}, func(abspath string, info os.FileInfo, depth int) bool {
		if strings.HasSuffix(info.Name(), "_test.rego") {
			return true
		}

		if !info.IsDir() && filepath.Ext(info.Name()) != ".rego" {
			return true
		}

		return false
	})
	if err != nil {
		return nil, fmt.Errorf("filter rego files: %w", err)
	}

	if _, err := result.Compiler(); err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	// Re-key the loaded rego file map based on the package path of the rego file.
	// This makes finding the source rego file from an import path much easier.
	files := make(map[string]*loader.RegoFile)
	for _, regoFile := range result.Modules {
		files[regoFile.Parsed.Package.Path.String()] = regoFile
	}

	var regos []Rego
	for _, file := range files {
		importPaths := getRecursiveImportPaths(file, files)
		importPaths = dedupe(importPaths)

		var dependencies []string
		for _, importPath := range importPaths {
			dependencies = append(dependencies, removeComments(string(files[importPath].Raw)))
		}

		var rules []string
		for r := range file.Parsed.Rules {
			rules = append(rules, file.Parsed.Rules[r].Head.Name.String())
		}

		var comments []string
		for c := range file.Parsed.Comments {
			comments = append(comments, trimString(string(file.Parsed.Comments[c].Text)))
		}

		// Many YAML parsers do not like rendering out CRLF when writing the YAML to disk.
		// This causes ConstraintTemplates to be rendered with the line breaks as text,
		// rather than the actual line break.
		raw := strings.ReplaceAll(string(file.Raw), "\r", "")

		rego := Rego{
			path:         file.Name,
			dependencies: dependencies,
			rules:        rules,
			comments:     comments,
			raw:          raw,
		}

		regos = append(regos, rego)
	}

	sort.Slice(regos, func(i, j int) bool {
		return regos[i].path < regos[j].path
	})

	return regos, nil
}

func removeComments(raw string) string {
	var regoWithoutComments string
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}

		regoWithoutComments += line + "\n"
	}

	return trimString(regoWithoutComments)
}

func trimString(text string) string {
	text = strings.TrimSpace(text)
	text = strings.Trim(text, "\n")
	return text
}

func getRecursiveImportPaths(regoFile *loader.RegoFile, regoFiles map[string]*loader.RegoFile) []string {
	var recursiveImports []string
	for i := range regoFile.Parsed.Imports {
		imported := regoFiles[regoFile.Parsed.Imports[i].Path.String()]

		recursiveImports = append(recursiveImports, imported.Parsed.Package.Path.String())
		recursiveImports = append(recursiveImports, getRecursiveImportPaths(imported, regoFiles)...)
	}

	return recursiveImports
}

func dedupe(collection []string) []string {
	var dedupedCollection []string
	for _, item := range collection {
		if contains(dedupedCollection, item) {
			continue
		}

		dedupedCollection = append(dedupedCollection, item)
	}

	return dedupedCollection
}

func contains(collection []string, item string) bool {
	for _, value := range collection {
		if strings.EqualFold(value, item) {
			return true
		}
	}

	return false
}
