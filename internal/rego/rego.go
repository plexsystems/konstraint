package rego

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Severity describes the severity level of the rego file.
type Severity string

// The defined severity levels represent the valid severity levels that a rego
// file can have.
const (
	Violation Severity = "Violation"
	Warning   Severity = "Warning"

	// PolicyIDVariable is the name of the variable that contains the policy identifier
	PolicyIDVariable = "policyID"
)

// Keys used in Custom section of OPA Rich Metadata Annotations
const (
	annoEnforcement    = "enforcement"
	annoMatchers       = "matchers"
	annoParameters     = "parameters"
	annoSkipConstraint = "skipConstraint"
)

// Rego represents a parsed rego file.
type Rego struct {
	id             string
	path           string
	raw            string
	sanitizedRaw   string
	headerComments []string
	rules          []string
	dependencies   []string
	parameters     []Parameter
	enforcement    string
	skipConstraint bool

	// Duplicate data from OPA Metadata annotations.
	annotations                   *ast.Annotations
	annoTitle                     string
	annoDescription               string
	annoParameters                map[string]apiextensionsv1.JSONSchemaProps
	annoKindMatchers              []AnnoKindMatcher
	annoNamespaceMatchers         []string
	annoExcludedNamespaceMatchers []string
	annoLabelSelector             *metav1.LabelSelector
}

type AnnoKindMatcher struct {
	APIGroups []string `json:"apiGroups,omitempty"`
	Kinds     []string `json:"kinds,omitempty"`
}

func (akm AnnoKindMatcher) String() string {
	var result string
	for _, apiGroup := range akm.APIGroups {
		if apiGroup == coreAPIShorthand {
			apiGroup = coreAPIGroup
		}
		for _, kind := range akm.Kinds {
			result += apiGroup + "/" + kind + " "
		}
	}
	return strings.TrimSpace(result)
}

// Parameter represents a parameter that the policy uses
type Parameter struct {
	Name        string
	Type        string
	IsArray     bool
	Description string
}

// GetAllSeverities gets all of the rego files found in the given directory as
// well as any subdirectories. Only rego files that contain a valid severity
// will be returned.
func GetAllSeverities(directory string) ([]Rego, error) {
	return getAllSeverities(directory, true)
}

// GetAllSeveritiesWithoutImports gets all of the Rego files found in the given
// directory as well as any subdirectories, but does not attempt to parse the
// imports.
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

// GetViolations gets all of the files found in the given directory as well as
// any subdirectories. Only rego files that have a severity of violation will
// be returned.
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

func (r Rego) AnnotationKindMatchers() []AnnoKindMatcher {
	return r.annoKindMatchers
}

func (r Rego) AnnotationNamespaceMatchers() []string {
	return r.annoNamespaceMatchers
}

func (r Rego) AnnotationExcludedNamespaceMatchers() []string {
	return r.annoExcludedNamespaceMatchers
}

func (r Rego) AnnotationLabelSelectorMatcher() *metav1.LabelSelector {
	return r.annoLabelSelector
}

func (r Rego) AnnotationParameters() map[string]apiextensionsv1.JSONSchemaProps {
	return r.annoParameters
}

func (r Rego) GetAnnotation(name string) (any, bool) {
	if r.annotations == nil {
		return nil, false
	}
	switch name {
	case "title":
		return r.annotations.Title, true
	case "description":
		return r.annotations.Description, true
	default:
		v, ok := r.annotations.Custom[name]
		return v, ok
	}
}

func (r *Rego) parseAnnotations(annotations *ast.Annotations) error {
	if annotations == nil {
		return nil
	}
	if annotations.Title != "" {
		r.annoTitle = annotations.Title
	}
	if annotations.Description != "" {
		r.annoDescription = annotations.Description
	}

	matchers, ok := annotations.Custom[annoMatchers]
	if ok {
		if err := r.parseAnnotationsMatchers(matchers.(map[string]any)); err != nil {
			return fmt.Errorf("parse matchers from OPA metadata: %w", err)
		}
	}

	parameters, ok := annotations.Custom[annoParameters]
	if ok {
		if err := r.parseAnnotationsParameters(parameters.(map[string]any)); err != nil {
			return fmt.Errorf("parse parameters from OPA metadata: %w", err)
		}
	}

	skipConstraint, ok := annotations.Custom[annoSkipConstraint]
	if ok {
		sc, ok := skipConstraint.(bool)
		if !ok {
			return fmt.Errorf("supplied skipConstraint value is not a bool: %T", skipConstraint)
		}
		r.skipConstraint = sc
	}

	enforcement, ok := annotations.Custom[annoEnforcement]
	if ok {
		e, ok := enforcement.(string)
		if !ok {
			return fmt.Errorf("supplied enforcement value is not a string: %T", enforcement)
		}
		r.enforcement = e
	}

	return nil
}

func (r *Rego) parseAnnotationsMatchers(matchers map[string]any) error {
	kindMatchers, ok := matchers["kinds"]
	if ok {
		km, err := remarshal[[]AnnoKindMatcher](kindMatchers)
		if err != nil {
			return fmt.Errorf("unmarshal kind matchers: %w", err)
		}
		r.annoKindMatchers = km
	}

	namespaceMatchers, ok := matchers["namespaces"]
	if ok {
		ns, err := remarshal[[]string](namespaceMatchers)
		if err != nil {
			return fmt.Errorf("unmarshal namespaces matcher: %w", err)
		}
		r.annoNamespaceMatchers = ns
	}

	excludedNamespaceMatchers, ok := matchers["excludedNamespaces"]
	if ok {
		ens, err := remarshal[[]string](excludedNamespaceMatchers)
		if err != nil {
			return fmt.Errorf("unmarshal excludedNamespaces matcher: %w", err)
		}
		r.annoExcludedNamespaceMatchers = ens
	}

	labelSelector, ok := matchers["labelSelector"]
	if ok {
		ls, err := remarshal[metav1.LabelSelector](labelSelector)
		if err != nil {
			return fmt.Errorf("unmarshal labelSelector matcher: %w", err)
		}
		r.annoLabelSelector = &ls
	}

	return nil
}

func (r *Rego) parseAnnotationsParameters(parameters map[string]any) error {
	params, err := remarshal[map[string]apiextensionsv1.JSONSchemaProps](parameters)
	if err != nil {
		return fmt.Errorf("unmarshal parameters: %w", err)
	}
	r.annoParameters = params
	return nil
}

func remarshal[Type any, V any](v V) (Type, error) {
	var result Type
	bytes, err := json.Marshal(v)
	if err != nil {
		return result, fmt.Errorf("marshal value %v: %w", v, err)
	}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return result, fmt.Errorf("unmarshal to type %T: %w", result, err)
	}
	return result, nil
}

// Severity returns the severity of the rego file. When a rego file has
// multiple rules that are considered to be different severities, the first
// rule is chosen.
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

// Kind returns the Kubernetes Kind of the rego file. The kind of the rego file
// is determined by the name of the directory that the rego file exists in.
func (r Rego) Kind() string {
	kind := filepath.Base(filepath.Dir(r.Path()))
	kind = strings.ReplaceAll(kind, "-", " ")
	kind = cases.Title(language.AmericanEnglish).String(kind)
	kind = strings.ReplaceAll(kind, " ", "")

	return kind
}

// Name returns the name of the rego file. The name of the rego file is its
// kind as lowercase.
func (r Rego) Name() string {
	return strings.ToLower(r.Kind())
}

// Title returns the title found in the header comment of the rego file.
func (r Rego) Title() string {
	if r.annoTitle != "" {
		return r.annoTitle
	}

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

// Enforcement returns the enforcement action in the header comment. Defaults
// to deny if no enforcement action is specified.
func (r Rego) Enforcement() string {
	if r.enforcement != "" {
		return r.enforcement
	}
	return "deny"
}

func getEnforcementTag(headerComments []string) string {
	enforcement := ""
	for _, comment := range headerComments {
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

// PolicyID returns the identifier of the policy. The returned value will be a
// blank string if an id was not specified in the policy body.
func (r Rego) PolicyID() string {
	return r.id
}

// Description returns the entire description found in the header comment of
// the Rego file.
func (r Rego) Description() string {
	if r.annoDescription != "" {
		return r.annoDescription
	}

	var description string
	var handlingCodeBlock bool
	var handlingParamDescription bool

	for _, comment := range r.headerComments {
		if !handlingCodeBlock && !handlingParamDescription && commentStartsWith(comment, "@parameter") && strings.Contains(comment, "--") {
			handlingParamDescription = true
		} else if !handlingCodeBlock && handlingParamDescription && !commentStartsWith(comment, "--") {
			handlingParamDescription = false
		}

		if handlingParamDescription || commentStartsWith(comment, "@") {
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

// HasMetadataAnnotations checks whenether rego file has
// OPA Metadata Annotations
func (r Rego) HasMetadataAnnotations() bool {
	return r.annotations != nil
}

// ConvertedLegacyAnnotations holds OPA Metadata Annotations,
// which were converted from legacy style annotations
type ConvertedLegacyAnnotations struct {
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	Custom      map[string]any `json:"custom,omitempty"`
}

// ConvertLegacyAnnotations converts legacy annotations to ConvertedLegacyAnnotations
func (r Rego) ConvertLegacyAnnotations() (*ConvertedLegacyAnnotations, error) {
	custom := make(map[string]any)
	if r.enforcement != "" {
		custom[annoEnforcement] = r.enforcement
	}
	if r.skipConstraint {
		custom[annoSkipConstraint] = r.skipConstraint
	}
	if len(r.parameters) > 0 {
		custom[annoParameters] = r.GetOpenAPISchemaProperties()
	}

	matchers, err := r.Matchers()
	if err != nil {
		return nil, fmt.Errorf("cant get legacy matchers: %w", err)
	}

	matcherMap := make(map[string]any)

	if len(matchers.KindMatchers) > 0 {
		matcherMap["kinds"] = matchers.KindMatchers.ToSpec()
	}

	labelSelector := make(map[string]any)
	if len(matchers.MatchLabelsMatcher) > 0 {
		labelSelector["matchLabels"] = matchers.MatchLabelsMatcher
	}
	if len(matchers.MatchExpressionsMatcher) > 0 {
		labelSelector["matchExpressions"] = matchers.MatchExpressionsMatcher
	}
	if len(labelSelector) > 0 {
		matcherMap["labelSelector"] = labelSelector
	}

	if len(matchers.NamespaceMatcher) > 0 {
		matcherMap["namespaces"] = matchers.NamespaceMatcher
	}
	if len(matchers.ExcludedNamespaceMatcher) > 0 {
		matcherMap["excludedNamespaces"] = matchers.ExcludedNamespaceMatcher
	}

	if len(matcherMap) > 0 {
		custom[annoMatchers] = matcherMap
	}

	return &ConvertedLegacyAnnotations{
		Title:       r.Title(),
		Description: r.Description(),
		Custom:      custom,
	}, nil
}

func (r Rego) GetOpenAPISchemaProperties() map[string]apiextensionsv1.JSONSchemaProps {
	properties := make(map[string]apiextensionsv1.JSONSchemaProps)
	for _, p := range r.Parameters() {
		if p.IsArray {
			properties[p.Name] = apiextensionsv1.JSONSchemaProps{
				Type:        "array",
				Description: p.Description,
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{Type: p.Type},
				},
			}
		} else {
			properties[p.Name] = apiextensionsv1.JSONSchemaProps{
				Type:        p.Type,
				Description: p.Description,
			}
		}
	}

	return properties
}

// Source returns the original source code inside
// of the rego file without any comments.
func (r Rego) Source() string {
	return removeComments(r.sanitizedRaw)
}

// FullSource returns the original source code inside
// of the rego file including comments except the header
func (r Rego) FullSource() string {
	withoutHeader := removeHeaderComments(r.sanitizedRaw)

	return strings.Trim(withoutHeader, "\n\t ")
}

// LegacyConversionSource returns the original source code
// with comments except header,
// but doesn't trim any trailing whitespace
func (r Rego) LegacyConversionSource() string {
	return removeHeaderComments(r.raw)
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

// Dependencies returns all of the source for the rego files that this rego
// file depends on.
func (r Rego) Dependencies() []string {
	return r.dependencies
}

// SkipConstraint returns whether or not the generation of the Constraint
// should be skipped. It is only set to true when the @skip-constraint tag is
// present in the comment header block
func (r Rego) SkipConstraint() bool {
	return r.skipConstraint
}

func parseDirectory(directory string, parseImports bool) ([]Rego, error) {
	// Recursively find all rego files (ignoring test files), starting at the given directory.
	result, err := loader.NewFileLoader().WithProcessAnnotation(true).Filtered([]string{directory}, func(abspath string, info os.FileInfo, depth int) bool {
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
			dependencies = append(dependencies, removeComments(sanitizeRawSource(files[importPath].Raw)))
		}

		var rules []string
		for r := range file.Parsed.Rules {
			rules = append(rules, file.Parsed.Rules[r].Head.Name.String())
		}

		var annotations *ast.Annotations
		for _, a := range file.Parsed.Annotations {
			if a.Scope == "package" {
				annotations = a
				break
			}
		}

		var headerComments []string
		for _, c := range file.Parsed.Comments {
			// If the line number of the comment comes before the line number
			// that the package is declared on, we can safely assume that it is
			// a header comment.
			if c.Location.Row < file.Parsed.Package.Location.Row {
				headerComments = append(headerComments, string(c.Text))
			} else {
				break
			}
		}

		bodyParams := getRuleParamNames(file.Parsed.Rules)
		var paramsDiff []string

		var headerParams []Parameter
		if annotations == nil {
			headerParams, err = getHeaderParamsLegacy(headerComments)
			if err != nil {
				return nil, fmt.Errorf("parse header parameters: %w", err)
			}
			paramsDiff = paramDiff(bodyParams, headerParams)
		} else {
			tempHeaderParams := getHeaderParams(annotations)
			paramsDiff = paramDiff(bodyParams, tempHeaderParams)
		}

		if len(paramsDiff) > 0 {
			return nil, fmt.Errorf("missing definitions for parameters %v found in the policy `%s`", paramsDiff, file.Name)
		}

		rego := Rego{
			id:             getPolicyID(file.Parsed.Rules),
			path:           file.Name,
			dependencies:   dependencies,
			rules:          rules,
			parameters:     headerParams,
			headerComments: headerComments,
			raw:            string(file.Raw),
			sanitizedRaw:   sanitizeRawSource(file.Raw),
			skipConstraint: hasSkipConstraintTag(headerComments),
			enforcement:    getEnforcementTag(headerComments),
			annotations:    annotations,
		}

		if annotations != nil {
			if err := rego.parseAnnotations(annotations); err != nil {
				return nil, fmt.Errorf("parse OPA Metadata annotations: %w", err)
			}
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

func sanitizeRawSource(raw []byte) string {
	// Many YAML parsers have problems handling carriage returns and tabs so we sanitize the Rego
	// before storing it so it can be rendered properly.
	raw = bytes.ReplaceAll(raw, []byte("\r"), []byte(""))
	raw = bytes.ReplaceAll(raw, []byte("\t"), []byte("  "))
	return trimEachLine(string(raw))
}

func getRuleParamNames(rules []*ast.Rule) []string {
	re := regexp.MustCompile(`input\.parameters\.([a-zA-Z0-9_-]+)`)
	var ruleParams []string
	for _, r := range rules {
		matches := re.FindAllStringSubmatch(r.String(), -1)
		for _, match := range matches {
			if !contains(ruleParams, match[1]) {
				ruleParams = append(ruleParams, match[1])
			}
		}
	}

	return ruleParams
}

func getHeaderParams(annotations *ast.Annotations) []Parameter {
	params, ok := annotations.Custom[annoParameters].(map[string]any)
	if !ok {
		return nil
	}
	var parameters []Parameter
	for p := range params {
		parameters = append(parameters, Parameter{Name: p})
	}

	return parameters
}

func getHeaderParamsLegacy(comments []string) ([]Parameter, error) {
	var parameters []Parameter
	for i := 0; i < len(comments); i++ {
		comment := comments[i]

		if !commentStartsWith(comment, "@parameter ") {
			continue
		}

		params := strings.SplitAfter(comment, "@parameter ")[1]
		paramsDesc := strings.SplitN(params, " --", 2)
		params = paramsDesc[0]
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

		if len(paramsDesc) > 1 {
			p.Description = strings.TrimSpace(paramsDesc[1])

			for i++; i != len(comments); i++ {
				extraComment := strings.TrimSpace(comments[i])
				if !strings.HasPrefix(extraComment, "--") {
					i--
					break
				}
				extraComment = strings.TrimSpace(extraComment[2:])
				p.Description += " " + extraComment
			}

			p.Description = strings.TrimSpace(p.Description)
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
		if !strings.HasPrefix(importPath, "data.lib.") {
			continue
		}

		imported := regoFiles[importPath]
		if imported == nil {
			// It is possible that the import is for a specific rule in a package
			// rather than for the package itself. To check for this, we remove
			// the last element in the import path and check again.
			split := strings.Split(importPath, ".")
			parent := strings.Join(split[0:len(split)-1], ".")
			imported = regoFiles[parent]
			if imported == nil {
				return nil, fmt.Errorf("import not found: %s", importPath)
			}
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
