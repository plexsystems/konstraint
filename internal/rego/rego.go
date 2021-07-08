package rego

import (
	"bytes"
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
	return getAllSeverities(directory, true)
}

// GetAllSeveritiesWithoutImports gets all of the Rego files found
// in the given directory as well as any subdirectories, but does
// not attempt to parse the imports.
func GetAllSeveritiesWithoutImports(directory string) ([]Rego, error) {
	return getAllSeverities(directory, false)
}

func getAllSeverities(directory string, parseImports bool) ([]Rego, error) {
	regos, err := parseDirectory(directory, parseImports)
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
	regos, err := parseDirectory(directory, true)
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
		if !commentStartsWith(comment, "@title") {
			continue
		}

		title = strings.SplitAfter(comment, "@title")[1]
		break
	}

	title = strings.TrimSpace(title)
	title = strings.Trim(title, "\n")
	return title
}

// Enforcement returns the enforcement action in the header comment
// Defaults to deny if no enforcement action is specified
func (r Rego) Enforcement() string {
	enforcement := "deny"
	for _, comment := range r.headerComments {
		if !commentStartsWith(comment, "@enforcement") {
			continue
		}

		enforcement = strings.SplitAfter(comment, "@enforcement")[1]
		break
	}

	enforcement = strings.TrimSpace(enforcement)
	enforcement = strings.Trim(enforcement, "\n")
	return enforcement
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
	var handlingCodeBlock bool
	for _, comment := range r.headerComments {
		if commentStartsWith(comment, "@") {
			continue
		}

		// By default, we trim the comments found in the header to produce better looking documentation.
		// However, when a comment in the Rego starts with a code block, we do not want to format
		// any of the text within the code block.
		if commentStartsWith(comment, "```") {

			// Everytime we see a code block marker, we want to flip the status of whether or
			// not we are currently handling a code block.
			//
			// i.e. The first time we see a codeblock marker we are handling a codeblock.
			//      The second time we see a codeblock marker, we are no longer handling that codeblock.
			handlingCodeBlock = !handlingCodeBlock
		}

		if handlingCodeBlock {
			description += comment
		} else {
			description += strings.TrimSpace(comment)
		}

		description += "\n"
	}

	description = strings.Trim(description, "\n")
	return description
}

// Source returns the original source code inside
// of the rego file without any comments.
func (r Rego) Source() string {
	return removeComments(r.raw)
}

// FullSource returns the original source code inside
// of the rego file including comments except the header
func (r Rego) FullSource() string {
	withoutHeader := removeHeaderComments(r.raw)

	return strings.Trim(withoutHeader, "\n\t ")
}

func removeHeaderComments(input string) string {
	var result string
	split := strings.Split(input, "\n")
	for i, line := range split {
		if !strings.HasPrefix(line, "#") {
			result = strings.Join(split[i:len(split)-1], "\n")
			break
		}
	}

	return result
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

func parseDirectory(directory string, parseImports bool) ([]Rego, error) {

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

	files := make(map[string]*loader.RegoFile)
	for m := range result.Modules {
		// Many YAML parsers have problems handling carriage returns and tabs so we sanitize the Rego
		// before storing it so it can be rendered properly.
		result.Modules[m].Raw = bytes.ReplaceAll(result.Modules[m].Raw, []byte("\r"), []byte(""))
		result.Modules[m].Raw = bytes.ReplaceAll(result.Modules[m].Raw, []byte("\t"), []byte("  "))

		// Re-key the loaded rego file map based on the package path of the rego file.
		// This makes finding the source rego file from an import path much easier.
		files[result.Modules[m].Parsed.Package.Path.String()] = result.Modules[m]
	}

	var regos []Rego
	for _, file := range files {
		var importPaths []string
		if parseImports {
			importPaths, err = getRecursiveImportPaths(file, files)
			if err != nil {
				return nil, fmt.Errorf("getRecursiveImportPaths: %w", err)
			}
			importPaths = dedupe(importPaths)
		}

		var dependencies []string
		for _, importPath := range importPaths {
			dependencies = append(dependencies, removeComments(string(files[importPath].Raw)))
		}

		var rules []string
		for r := range file.Parsed.Rules {
			rules = append(rules, file.Parsed.Rules[r].Head.Name.String())
		}

		var headerComments []string
		for _, c := range file.Parsed.Comments {

			// If the line number of the comment comes before the line number
			// that the package is declared on, we can safely assume that it is
			// a header comment.
			if c.Location.Row < file.Parsed.Package.Location.Row {
				headerComments = append(headerComments, string(c.Text))
			}
		}

		bodyParams := getBodyParamNames(file.Parsed.Rules)
		headerParams, err := getHeaderParams(headerComments)
		if err != nil {
			return nil, fmt.Errorf("parse header parameters: %w", err)
		}

		paramsDiff := paramDiff(bodyParams, headerParams)
		if len(paramsDiff) > 0 {
			return nil, fmt.Errorf("missing @parameter tags for parameters %v found in the policy: %v", paramsDiff, file.Name)
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

		rego := Rego{
			id:             getPolicyID(file.Parsed.Rules),
			path:           file.Name,
			dependencies:   dependencies,
			rules:          rules,
			parameters:     headerParams,
			headerComments: headerComments,
			raw:            trimEachLine(string(file.Raw)),
			skipConstraint: hasSkipConstraintTag(headerComments),
		}

		regos = append(regos, rego)
	}

	// Sort the Rego files by their paths so that they can be rendered consistently
	// for documentation purposes.
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
			if !contains(bodyParams, match[2]) {
				bodyParams = append(bodyParams, match[2])
			}
		}
	}

	return bodyParams
}

func getHeaderParams(comments []string) ([]Parameter, error) {
	var parameters []Parameter
	for _, comment := range comments {
		if !commentStartsWith(comment, "@parameter") {
			continue
		}

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

	return parameters, nil
}

func trimEachLine(raw string) string {
	var result string

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		result += strings.TrimRight(line, "\t ") + "\n"
	}

	return result
}

func hasSkipConstraintTag(comments []string) bool {
	for _, comment := range comments {
		if commentStartsWith(comment, "@skip-constraint") {
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

	regoWithoutComments = strings.TrimSpace(regoWithoutComments)
	regoWithoutComments = strings.Trim(regoWithoutComments, "\n")
	return regoWithoutComments
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
			return nil, fmt.Errorf("get recursive import paths: %w", err)
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

func paramDiff(bodyParams []string, headerParams []Parameter) []string {
	var hps []string
	for _, hp := range headerParams {
		hps = append(hps, hp.Name)
	}

	var res []string
	for _, bp := range bodyParams {
		if !contains(hps, bp) {
			res = append(res, bp)
		}
	}

	return res
}
