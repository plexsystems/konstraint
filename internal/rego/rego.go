package rego

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
)

// Severity describes the severity level of the rego file.
type Severity string

// The defined severity levels represent the valid severity
// levels that a rego file can have.
const (
	Violation Severity = "Violation"
	Warning   Severity = "Warning"

	// PolicyIDVariable is the name of the variable that contains the policy identifier
	PolicyIDVariable = "policyID"
)

// Rego represents a parsed rego file.
type Rego struct {
	id             string
	path           string
	raw            string
	comments       []string
	headerComments []string
	rules          []string
	dependencies   []string
	parameters     []Parameter
	skipConstraint bool
}

// Parameter represents a parameter that the policy uses
type Parameter struct {
	Name    string
	Type    string
	IsArray bool
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

// Parameters returns the list of parsed parameters
func (r Rego) Parameters() []Parameter {
	return r.parameters
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
	for _, comment := range r.headerComments {
		if !strings.Contains(comment, "@title") {
			continue
		}

		title = strings.SplitAfter(comment, "@title")[1]
		break
	}

	return trimString(title)
}

// Enforcement returns the enforcement action in the header comment
// Defaults to deny if no enforcement action is specified
func (r Rego) Enforcement() string {
	enforcement := "deny"
	for _, comment := range r.headerComments {
		if !strings.Contains(comment, "@enforcement") {
			continue
		}

		enforcement = strings.SplitAfter(comment, "@enforcement")[1]
		break
	}

	return trimString(enforcement)
}

// PolicyID returns the identifier of the policy
// The returned value will be a blank string if an id was not specified in the policy body
func (r Rego) PolicyID() string {
	return r.id
}

// Description returns the entire description
// found in the header comment of the rego file.
func (r Rego) Description() string {
	var description string
	for _, comment := range r.headerComments {
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

// SkipConstraint returns whether or not the generation of the Constraint should be skipped
// It is only set to true when the @skip-constraint tag is present in the comment header block
func (r Rego) SkipConstraint() bool {
	return r.skipConstraint
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
		importPaths, err := getRecursiveImportPaths(file, files)
		if err != nil {
			return nil, fmt.Errorf("getRecursiveImportPaths: %w", err)
		}
		importPaths = dedupe(importPaths)

		var dependencies []string
		for _, importPath := range importPaths {
			dependencies = append(dependencies, removeComments(string(files[importPath].Raw)))
		}

		var rules []string
		for r := range file.Parsed.Rules {
			rules = append(rules, file.Parsed.Rules[r].Head.Name.String())
		}

		var headerComments, comments []string
		for _, c := range file.Parsed.Comments {
			if c.Location.Row < file.Parsed.Package.Location.Row {
				headerComments = append(headerComments, trimString(string(c.Text)))
			} else {
				comments = append(comments, trimString(string(c.Text)))
			}
		}

		bodyParams := getBodyParamNames(file.Parsed.Rules)
		headerParams, err := getHeaderParams(headerComments)
		if err != nil {
			return nil, fmt.Errorf("parse header parameters: %w", err)
		}
		if len(bodyParams) != len(headerParams) {
			return nil, fmt.Errorf("count of @parameter tags does not match parameter count")
		}
		for _, bodyParam := range bodyParams {
			var seen bool
			for _, headerParam := range headerParams {
				if headerParam.Name == bodyParam {
					seen = true
					break
				}
			}

			if !seen {
				return nil, fmt.Errorf("missing @parameter tag for parameter: %s", bodyParam)
			}
		}

		// Many YAML parsers do not like rendering out CRLF when writing the YAML to disk.
		// This causes ConstraintTemplates to be rendered with the line breaks as text,
		// rather than the actual line break.
		raw := strings.ReplaceAll(string(file.Raw), "\r", "")

		rego := Rego{
			id:             getPolicyID(file.Parsed.Rules),
			path:           file.Name,
			dependencies:   dependencies,
			rules:          rules,
			parameters:     headerParams,
			headerComments: headerComments,
			comments:       comments,
			raw:            raw,
			skipConstraint: hasSkipConstraintTag(headerComments),
		}

		regos = append(regos, rego)
	}

	sort.Slice(regos, func(i, j int) bool {
		return regos[i].path < regos[j].path
	})

	return regos, nil
}

func getBodyParamNames(rules []*ast.Rule) []string {
	r := regexp.MustCompile(`(core|input)\.parameters\.([a-zA-Z0-9_-]+)`)
	var bodyParams []string
	for _, rule := range rules {
		matches := r.FindAllStringSubmatch(rule.Body.String(), -1)
		for _, match := range matches {
			bodyParams = append(bodyParams, match[2]) // the 0 index is the full match, we only care about the second group
		}
	}
	bodyParams = dedupe(bodyParams) // possible a param is referenced more than once

	return bodyParams
}

func getHeaderParams(comments []string) ([]Parameter, error) {
	var parameters []Parameter
	for _, comment := range comments {
		if strings.HasPrefix(comment, "@parameter") {
			params := strings.SplitAfter(comment, "@parameter ")[1]
			paramsSplit := strings.Split(params, " ")
			if len(paramsSplit) == 0 {
				return nil, fmt.Errorf("parameter name and type must be specified")
			}
			if len(paramsSplit) == 1 {
				return nil, fmt.Errorf("type must be supplied with parameter name: %s", paramsSplit[0])
			}

			p := Parameter{Name: paramsSplit[0]}
			if paramsSplit[1] == "array" {
				if len(paramsSplit) == 2 {
					return nil, fmt.Errorf("array type must be supplied with parameter name: %s", paramsSplit[0])
				}
				p.IsArray = true
				p.Type = paramsSplit[2]
			} else {
				p.Type = paramsSplit[1]
			}

			parameters = append(parameters, p)
		}
	}

	return parameters, nil
}

func hasSkipConstraintTag(comments []string) bool {
	for _, comment := range comments {
		if strings.HasPrefix(comment, "@skip-constraint") {
			return true
		}
	}

	return false
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

func getPolicyID(rules []*ast.Rule) string {
	var policyID string
	for _, rule := range rules {
		if rule.Head.Name.String() == PolicyIDVariable {
			policyID = strings.ReplaceAll(rule.Head.Value.Value.String(), `"`, "")
			break
		}
	}

	return policyID
}

func trimString(text string) string {
	text = strings.TrimSpace(text)
	text = strings.Trim(text, "\n")
	return text
}

func getRecursiveImportPaths(regoFile *loader.RegoFile, regoFiles map[string]*loader.RegoFile) ([]string, error) {
	var recursiveImports []string
	for i := range regoFile.Parsed.Imports {
		importPath := regoFile.Parsed.Imports[i].Path.String()
		imported := regoFiles[importPath]
		if imported == nil {
			return nil, fmt.Errorf("import not found: %s", importPath)
		}

		recursiveImports = append(recursiveImports, imported.Parsed.Package.Path.String())
		remainingImports, err := getRecursiveImportPaths(imported, regoFiles)
		if err != nil {
			return nil, err
		}
		recursiveImports = append(recursiveImports, remainingImports...)
	}

	return recursiveImports, nil
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
