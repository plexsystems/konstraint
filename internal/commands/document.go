package commands

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/plexsystems/konstraint/internal/rego"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Header is the header comment block found on a Rego policy.
type Header struct {
	Title       string
	Description string
	Resources   []string
	MatchLabels string
	Anchor      string
	Parameters  []rego.Parameter
}

// Document is a single policy document.
type Document struct {
	Header Header
	URL    string
	Rego   string
}

//go:embed document_template.tpl
var docTemplate string

func newDocCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "doc <dir>",
		Short: "Generate documentation from Rego policies",
		Example: `Generate the documentation
	konstraint doc

Save the documentation to a specific directory
	konstraint doc --output docs/policies.md

Set the URL where the policies are hosted at
	konstraint doc --url https://github.com/plexsystems/konstraint`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("output", cmd.Flags().Lookup("output")); err != nil {
				return fmt.Errorf("bind output flag: %w", err)
			}

			if err := viper.BindPFlag("template-file", cmd.Flags().Lookup("template-file")); err != nil {
				return fmt.Errorf("bind template-file flag: %w", err)
			}

			if err := viper.BindPFlag("url", cmd.Flags().Lookup("url")); err != nil {
				return fmt.Errorf("bind url flag: %w", err)
			}

			if err := viper.BindPFlag("no-rego", cmd.Flags().Lookup("no-rego")); err != nil {
				return fmt.Errorf("bind no-rego flag: %w", err)
			}

			if err := viper.BindPFlag("include-comments", cmd.Flags().Lookup("include-comments")); err != nil {
				return fmt.Errorf("bind include-comments flag: %w", err)
			}

			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runDocCommand(path)
		},
	}

	cmd.Flags().StringP("output", "o", "policies.md", "Output location (including filename) for the policy documentation")
	cmd.Flags().String("template-file", "", `File to read the template from (default: "")`)
	cmd.Flags().String("url", "", "The URL where the policy files are hosted at (e.g. https://github.com/policies)")
	cmd.Flags().Bool("no-rego", false, "Do not include the Rego in the policy documentation")
	cmd.Flags().Bool("include-comments", false, "Include comments from the rego source in the documentation")

	return &cmd
}

func runDocCommand(path string) error {
	outputDirectory := filepath.Dir(viper.GetString("output"))
	appliedTemplate := docTemplate

	if err := os.MkdirAll(outputDirectory, os.ModePerm); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	docs, err := getDocumentation(path, outputDirectory)
	if err != nil {
		return fmt.Errorf("get documentation: %w", err)
	}

	if file := viper.GetString("template-file"); file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("unable to open/read template file: %w", err)
		}
		appliedTemplate = string(b)
	}

	t, err := template.New("docs").Parse(appliedTemplate)

	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	f, err := os.OpenFile(viper.GetString("output"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("opening file for writing: %w", err)
	}

	if err := t.Execute(f, docs); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	var numPolicies int
	for _, policies := range docs {
		numPolicies += len(policies)
	}
	log.WithField("num_policies", numPolicies).Info("completed successfully")

	return nil
}

func getDocumentation(path string, outputDirectory string) (map[rego.Severity][]Document, error) {
	policies, err := rego.GetAllSeveritiesWithoutImports(path)
	if err != nil {
		return nil, fmt.Errorf("get all severities: %w", err)
	}

	if viper.GetBool("no-rego") {
		log.Info("no-rego flag is set. Policy source will not be included in the documentation.")
	}

	documents := make(map[rego.Severity][]Document)
	for _, policy := range policies {
		logger := log.WithFields(log.Fields{
			"name": policy.Kind(),
			"src":  policy.Path(),
		})

		if policy.Title() == "" {
			logger.Warn("No title set, skipping documentation generation.")
			continue
		}

		var url string
		if viper.GetString("url") != "" {
			url = viper.GetString("url") + "/" + policy.Path()
		} else {
			outputDirectory, err := filepath.Abs(outputDirectory)
			if err != nil {
				return nil, fmt.Errorf("get abs path of output dir: %w", err)
			}
			policyPath, err := filepath.Abs(policy.Path())
			if err != nil {
				return nil, fmt.Errorf("get abs path of policy: %w", err)
			}
			relPath, err := filepath.Rel(outputDirectory, policyPath)
			if err != nil {
				return nil, fmt.Errorf("rel path: %w", err)
			}
			relDir := filepath.Dir(relPath)

			// Markdown specification notes that all pathing should be represented
			// with a forward slash.
			url = strings.ReplaceAll(relDir, string(os.PathSeparator), "/")
		}

		documentTitle := policy.Title()
		if policy.PolicyID() != "" {
			documentTitle = fmt.Sprintf("%s: %s", policy.PolicyID(), documentTitle)
		}

		anchor := strings.ToLower(strings.ReplaceAll(documentTitle, " ", "-"))
		anchor = strings.ReplaceAll(anchor, ":", "")

		var matchResources []string
		if len(policy.AnnotationKindMatchers()) > 0 {
			for _, akm := range policy.AnnotationKindMatchers() {
				s := strings.Split(akm.String(), " ")
				matchResources = append(matchResources, s...)
			}
		}
		if len(matchResources) == 0 {
			logger.Warn("No kind matchers set, this can lead to poor policy performance.")
			matchResources = append(matchResources, "Any Resource")
		}

		var matchLabels string
		if policy.AnnotationLabelSelectorMatcher() != nil {
			matchLabels = labelSelectorDocString(policy.AnnotationLabelSelectorMatcher())
		}

		parameters := annoParamsToLegacyFormat(policy.AnnotationParameters())
		sort.Slice(parameters, func(i, j int) bool {
			return parameters[i].Name < parameters[j].Name
		})

		header := Header{
			Title:       documentTitle,
			Description: policy.Description(),
			Resources:   matchResources,
			MatchLabels: matchLabels,
			Anchor:      anchor,
			Parameters:  parameters,
		}

		var rego string
		if viper.GetBool("include-comments") {
			rego = policy.FullSource()
		} else {
			rego = policy.Source()
		}
		if viper.GetBool("no-rego") {
			rego = ""
		}
		document := Document{
			Header: header,
			URL:    url,
			Rego:   rego,
		}

		if policy.Severity() == "" {
			documents["Other"] = append(documents["Other"], document)
		} else if policy.Enforcement() == "dryrun" {
			documents["Not Enforced"] = append(documents["Not Enforced"], document)
		} else {
			documents[policy.Severity()] = append(documents[policy.Severity()], document)
		}
	}

	sortPoliciesByTitle(documents)
	return documents, nil
}

func labelSelectorDocString(selector *metav1.LabelSelector) string {
	var result string
	for k, v := range selector.MatchLabels {
		result += fmt.Sprintf("%s=%s, ", k, v)
	}
	for _, expr := range selector.MatchExpressions {
		result += fmt.Sprintf("%s %s %v, ", expr.Key, expr.Operator, expr.Values)
	}

	return strings.TrimSuffix(result, ", ")
}

func annoParamsToLegacyFormat(parameters map[string]apiextensionsv1.JSONSchemaProps) []rego.Parameter {
	var results []rego.Parameter
	for param, config := range parameters {
		if config.Type == "array" {
			results = append(results, rego.Parameter{
				Name:        param,
				Description: config.Description,
				IsArray:     true,
				Type:        config.Items.Schema.Type,
			})
		} else {
			results = append(results, rego.Parameter{
				Name:        param,
				Description: config.Description,
				Type:        config.Type,
			})
		}
	}
	return results
}

func sortPoliciesByTitle(policyMap map[rego.Severity][]Document) {
	for _, documents := range policyMap {
		sort.Slice(documents, func(i, j int) bool {
			return documents[i].Header.Title < documents[j].Header.Title
		})
	}
}
