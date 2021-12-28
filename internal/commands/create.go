package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/plexsystems/konstraint/internal/rego"

	"github.com/ghodss/yaml"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func newCreateCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "create <dir>",
		Short: "Create Gatekeeper constraints from Rego policies",
		Example: `Create constraints in the same directories as the policies
	konstraint create examples

Save the constraints in a specific directory
	konstraint create examples --output generated-constraints

Create constraints with the Gatekeeper enforcement action set to dryrun
	konstraint create examples --dryrun`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("dryrun", cmd.PersistentFlags().Lookup("dryrun")); err != nil {
				return fmt.Errorf("bind dryrun flag: %w", err)
			}

			if err := viper.BindPFlag("output", cmd.PersistentFlags().Lookup("output")); err != nil {
				return fmt.Errorf("bind output flag: %w", err)
			}

			if err := viper.BindPFlag("skip-constraints", cmd.PersistentFlags().Lookup("skip-constraints")); err != nil {
				return fmt.Errorf("bind skip-constraints flag: %w", err)
			}

			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runCreateCommand(path)
		},
	}

	cmd.PersistentFlags().StringP("output", "o", "", "Specify an output directory for the Gatekeeper resources")
	cmd.PersistentFlags().BoolP("dryrun", "d", false, "Sets the enforcement action of the constraints to dryrun, overriding the @enforcement tag")
	cmd.PersistentFlags().Bool("skip-constraints", false, "Skip generation of constraints")

	return &cmd
}

func runCreateCommand(path string) error {
	violations, err := rego.GetViolations(path)
	if err != nil {
		return fmt.Errorf("get violations: %w", err)
	}

	for _, violation := range violations {
		logger := log.WithFields(log.Fields{
			"name": violation.Kind(),
			"src":  violation.Path(),
		})

		if !isValidEnforcementAction(violation.Enforcement()) {
			return fmt.Errorf("enforcement action (%v) is invalid in policy: %s", violation.Enforcement(), violation.Path())
		}

		templateFileName := "template.yaml"
		constraintFileName := "constraint.yaml"
		outputDir := filepath.Dir(violation.Path())
		if viper.GetString("output") != "" {
			outputDir = viper.GetString("output")
			templateFileName = fmt.Sprintf("template_%s.yaml", violation.Kind())
			constraintFileName = fmt.Sprintf("constraint_%s.yaml", violation.Kind())
		}

		if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}

		constraintTemplate := getConstraintTemplate(violation)
		constraintTemplateBytes, err := yaml.Marshal(&constraintTemplate)
		if err != nil {
			return fmt.Errorf("marshal constrainttemplate: %w", err)
		}

		if err := ioutil.WriteFile(filepath.Join(outputDir, templateFileName), constraintTemplateBytes, 0644); err != nil {
			return fmt.Errorf("writing template: %w", err)
		}

		if viper.GetBool("skip-constraints") || violation.SkipConstraint() {
			logger.Info("skipping constraint generation due to configuration")
			continue
		}

		// Skip Constraint generation if there are parameters on the template.
		if len(violation.Parameters()) > 0 {
			logger.Warn("skipping constraint generation due to use of parameters")
			continue
		}

		constraint, err := getConstraint(violation)
		if err != nil {
			return fmt.Errorf("get constraint: %w", err)
		}

		constraintBytes, err := yaml.Marshal(&constraint)
		if err != nil {
			return fmt.Errorf("marshal constraint: %w", err)
		}

		if err := ioutil.WriteFile(filepath.Join(outputDir, constraintFileName), constraintBytes, 0644); err != nil {
			return fmt.Errorf("writing constraint: %w", err)
		}
	}

	log.WithField("num_policies", len(violations)).Info("completed successfully")

	return nil
}

func getConstraintTemplate(violation rego.Rego) v1beta1.ConstraintTemplate {
	constraintTemplate := v1beta1.ConstraintTemplate{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "templates.gatekeeper.sh/v1beta1",
			Kind:       "ConstraintTemplate",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: violation.Name(),
		},
		Spec: v1beta1.ConstraintTemplateSpec{
			CRD: v1beta1.CRD{
				Spec: v1beta1.CRDSpec{
					Names: v1beta1.Names{
						Kind: violation.Kind(),
					},
				},
			},
			Targets: []v1beta1.Target{
				{
					Target: "admission.k8s.gatekeeper.sh",
					Libs:   violation.Dependencies(),
					Rego:   violation.Source(),
				},
			},
		},
	}

	if len(violation.Parameters()) > 0 {
		constraintTemplate.Spec.CRD.Spec.Validation = &v1beta1.Validation{
			OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{
				Properties: getOpenAPISchemaProperties(violation),
			},
		}
	}

	return constraintTemplate
}

func getOpenAPISchemaProperties(r rego.Rego) map[string]apiextensionsv1beta1.JSONSchemaProps {
	properties := make(map[string]apiextensionsv1beta1.JSONSchemaProps)
	for _, p := range r.Parameters() {
		if p.IsArray {
			properties[p.Name] = apiextensionsv1beta1.JSONSchemaProps{
				Type: "array",
				Items: &apiextensionsv1beta1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1beta1.JSONSchemaProps{Type: p.Type},
				},
			}
		} else {
			properties[p.Name] = apiextensionsv1beta1.JSONSchemaProps{Type: p.Type}
		}
	}

	return properties
}

func getConstraint(violation rego.Rego) (unstructured.Unstructured, error) {
	gvk := schema.GroupVersionKind{
		Group:   "constraints.gatekeeper.sh",
		Version: "v1beta1",
		Kind:    violation.Kind(),
	}

	constraint := unstructured.Unstructured{}
	constraint.SetGroupVersionKind(gvk)
	constraint.SetName(violation.Name())

	if violation.Enforcement() != "deny" {
		if err := unstructured.SetNestedField(constraint.Object, violation.Enforcement(), "spec", "enforcementAction"); err != nil {
			return unstructured.Unstructured{}, fmt.Errorf("set constraint enforcement: %w", err)
		}
	}

	// The dryrun flag overrides any enforcement action specified in the rego header.
	dryrun := viper.GetBool("dryrun")
	if dryrun {
		if err := unstructured.SetNestedField(constraint.Object, "dryrun", "spec", "enforcementAction"); err != nil {
			return unstructured.Unstructured{}, fmt.Errorf("set constraint dryrun: %w", err)
		}
	}

	matchers, err := violation.Matchers()
	if err != nil {
		return unstructured.Unstructured{}, fmt.Errorf("matchers: %w", err)
	}

	if len(matchers.KindMatchers) != 0 {
		if err := setKindMatcher(&constraint, matchers.KindMatchers); err != nil {
			return unstructured.Unstructured{}, fmt.Errorf("set kind matcher: %w", err)
		}
	}

	if len(matchers.MatchLabelsMatcher) != 0 {
		if err := setMatchLabelsMatcher(&constraint, matchers.MatchLabelsMatcher); err != nil {
			return unstructured.Unstructured{}, fmt.Errorf("set match labels matcher: %w", err)
		}
	}

	return constraint, nil
}

func setKindMatcher(constraint *unstructured.Unstructured, kindMatchers []rego.KindMatcher) error {
	var kinds []string
	var apiGroups []string
	for _, kindMatcher := range kindMatchers {
		kinds = appendIfNotExists(kinds, kindMatcher.Kind)
	}

	for _, kindMatcher := range kindMatchers {
		apiGroup := kindMatcher.APIGroup
		if kindMatcher.APIGroup == "core" {
			apiGroup = ""
		}

		apiGroups = appendIfNotExists(apiGroups, apiGroup)
	}

	constraintMatcher := map[string]interface{}{
		"apiGroups": toInterfaceSlice(apiGroups),
		"kinds":     toInterfaceSlice(kinds),
	}

	if err := unstructured.SetNestedSlice(constraint.Object, []interface{}{constraintMatcher}, "spec", "match", "kinds"); err != nil {
		return fmt.Errorf("set constraint kinds matchers: %w", err)
	}
	return nil
}

func appendIfNotExists(currentItems []string, newItem string) []string {
	for _, item := range currentItems {
		if strings.EqualFold(newItem, item) {
			return currentItems
		}
	}
	return append(currentItems, newItem)
}

func toInterfaceSlice(input []string) []interface{} {
	res := make([]interface{}, len(input))
	for i, v := range input {
		res[i] = v
	}
	return res
}

func setMatchLabelsMatcher(constraint *unstructured.Unstructured, matcher rego.MatchLabelsMatcher) error {
	if err := unstructured.SetNestedStringMap(constraint.Object, matcher, "spec", "match", "labelSelector", "matchLabels"); err != nil {
		return fmt.Errorf("set constraint labelSelector.matchLabels matchers: %w", err)
	}
	return nil
}

func isValidEnforcementAction(action string) bool {
	for _, a := range []string{"deny", "dryrun", "warn"} {
		if a == action {
			return true
		}
	}

	return false
}
