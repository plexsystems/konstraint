package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/plexsystems/konstraint/internal/rego"

	"github.com/go-sprout/sprout/sprigin"
	v1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

const (
	legacyMigrationMessage = " are set with legacy annotations, this functionality will be removed in a future release. Please migrate to OPA Metadata annotations. See konstraint convert."
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
			if err := viper.BindPFlag("constraint-template-version", cmd.PersistentFlags().Lookup("constraint-template-version")); err != nil {
				return fmt.Errorf("bind constraint-template-version flag: %w", err)
			}
			if err := viper.BindPFlag("constraint-template-custom-template-file", cmd.PersistentFlags().Lookup("constraint-template-custom-template-file")); err != nil {
				return fmt.Errorf("bind constraint-template-custom-template-file flag: %w", err)
			}
			if err := viper.BindPFlag("constraint-custom-template-file", cmd.PersistentFlags().Lookup("constraint-custom-template-file")); err != nil {
				return fmt.Errorf("bind constraint-custom-template-file flag: %w", err)
			}

			if err := viper.BindPFlag("partial-constraints", cmd.PersistentFlags().Lookup("partial-constraints")); err != nil {
				return fmt.Errorf("bind partial-constraints flag: %w", err)
			}

			if err := viper.BindPFlag("log-level", cmd.PersistentFlags().Lookup("log-level")); err != nil {
				return fmt.Errorf("bind log-level flag: %w", err)
			}

			if cmd.PersistentFlags().Lookup("constraint-template-custom-template-file").Changed && cmd.PersistentFlags().Lookup("constraint-template-version").Changed {
				return fmt.Errorf("need to set either constraint-template-custom-template-file or constraint-template-version")
			}
			if cmd.PersistentFlags().Lookup("log-level").Changed {
				level, err := log.ParseLevel(viper.GetString("log-level"))
				if err != nil {
					return fmt.Errorf("Unknown log level: Need to use either error, info, debug or trace")
				}
				log.SetLevel(level)
			}
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runCreateCommand(path)
		},
	}

	cmd.PersistentFlags().StringP("output", "o", "", "Specify an output directory for the Gatekeeper resources")
	cmd.PersistentFlags().BoolP("dryrun", "d", false, "Set the enforcement action of the constraints to dryrun, overriding the @enforcement tag")
	cmd.PersistentFlags().Bool("skip-constraints", false, "Skip generation of constraints")
	cmd.PersistentFlags().String("constraint-template-version", "v1", "Set the version of ConstraintTemplates")
	cmd.PersistentFlags().Bool("partial-constraints", false, "Generate partial Constraints for policies with parameters")
	cmd.PersistentFlags().String("constraint-template-custom-template-file", "", "Path to a custom template file to generate constraint templates")
	cmd.PersistentFlags().String("constraint-custom-template-file", "", "Path to a custom template file to generate constraints")
	cmd.PersistentFlags().String("log-level", "info", "Set a log level. Options: error, info, debug, trace")
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

		logger.Debug("Rendering policy")

		if violation.SkipTemplate() {
			logger.Info("Skipping constrainttemplate generation due to configuration")
			continue
		}

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

		constraintTemplateVersion := viper.GetString("constraint-template-version")
		constraintTemplateCustomTemplateFile := viper.GetString("constraint-template-custom-template-file")

		constraintTemplate, err := renderConstraintTemplate(violation, constraintTemplateVersion, constraintTemplateCustomTemplateFile, logger)
		if err != nil {
			return fmt.Errorf("rendering ConstraintTemplate: %w", err)
		}

		if err := os.WriteFile(filepath.Join(outputDir, templateFileName), constraintTemplate, 0644); err != nil {
			return fmt.Errorf("writing ConstraintTemplate: %w", err)
		}

		if viper.GetBool("skip-constraints") || violation.SkipConstraint() {
			logger.Info("Skipping constraint generation due to configuration")
			continue
		}

		// Skip Constraint generation if there are parameters on the template.
		if !viper.GetBool("partial-constraints") && (len(violation.Parameters()) > 0 || len(violation.AnnotationParameters()) > 0) {
			logger.Warn("Skipping constraint generation due to use of parameters")
			continue
		}

		constraintCustomTemplateFile := viper.GetString("constraint-custom-template-file")

		constraintBytes, err := renderConstraint(violation, constraintCustomTemplateFile, logger)

		if err != nil {
			return fmt.Errorf("rendering Constraint: %w", err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, constraintFileName), constraintBytes, 0644); err != nil {
			return fmt.Errorf("writing constraint: %w", err)
		}
	}

	log.WithField("num_policies", len(violations)).Info("completed successfully")

	return nil
}

func renderConstraintTemplate(violation rego.Rego, constraintTemplateVersion string, constraintTemplateCustomTemplateFile string, logger *log.Entry) ([]byte, error) {
	var constraintTemplate any
	var constraintTemplateBytes []byte

	if constraintTemplateCustomTemplateFile != "" {
		customTemplate, err := os.ReadFile(constraintTemplateCustomTemplateFile)
		if err != nil {
			return nil, fmt.Errorf("unable to open/read template file: %w", err)
		}
		constraintTemplateBytes, err = renderTemplate(violation, customTemplate)
		if err != nil {
			return nil, fmt.Errorf("unable to render custom template: %w", err)
		}
	} else {
		switch constraintTemplateVersion {
		case "v1":
			constraintTemplate = getConstraintTemplatev1(violation, logger)
		case "v1beta1":
			constraintTemplate = getConstraintTemplatev1beta1(violation, logger)
		default:
			return nil, fmt.Errorf("unsupported API version for constrainttemplate: %s", constraintTemplateVersion)
		}
		var err error
		constraintTemplateBytes, err = yaml.Marshal(constraintTemplate)

		if err != nil {
			return nil, fmt.Errorf("marshal constrainttemplate: %w", err)
		}
	}

	return constraintTemplateBytes, nil

}
func renderConstraint(violation rego.Rego, constraintCustomTemplateFile string, logger *log.Entry) ([]byte, error) {
	var constraintBytes []byte
	if constraintCustomTemplateFile != "" {
		customTemplate, err := os.ReadFile(constraintCustomTemplateFile)
		if err != nil {
			return nil, fmt.Errorf("unable to open/read template file: %w", err)
		}
		constraintBytes, err = renderTemplate(violation, customTemplate)
		if err != nil {
			return nil, fmt.Errorf("unable to render custom constraint: %w", err)
		}
	} else {
		constraint, err := getConstraint(violation, logger)
		if err != nil {
			return nil, fmt.Errorf("get constraint: %w", err)
		}

		constraintBytes, err = yaml.Marshal(constraint)
		if err != nil {
			return nil, fmt.Errorf("marshal constraint: %w", err)
		}
	}
	return constraintBytes, nil

}

func renderTemplate(violation rego.Rego, appliedTemplate []byte) ([]byte, error) {
	t, err := template.New("template").Funcs(sprigin.FuncMap()).Parse(string(appliedTemplate))
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}
	buf := new(bytes.Buffer)

	if err := t.Execute(buf, violation); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}

	return buf.Bytes(), nil
}

func getConstraintTemplatev1(violation rego.Rego, logger *log.Entry) *v1.ConstraintTemplate {
	constraintTemplate := v1.ConstraintTemplate{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "templates.gatekeeper.sh/v1",
			Kind:       "ConstraintTemplate",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: violation.Name(),
		},
		Spec: v1.ConstraintTemplateSpec{
			CRD: v1.CRD{
				Spec: v1.CRDSpec{
					Names: v1.Names{
						Kind: violation.Kind(),
					},
				},
			},
			Targets: []v1.Target{
				{
					Target: "admission.k8s.gatekeeper.sh",
					Libs:   violation.Dependencies(),
					Rego:   violation.Source(),
				},
			},
		},
	}

	if len(violation.Parameters()) > 0 {
		logger.Warn("Parameters" + legacyMigrationMessage)
		constraintTemplate.Spec.CRD.Spec.Validation = &v1.Validation{
			OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
				Properties: violation.GetOpenAPISchemaProperties(),
				Type:       "object",
			},
		}
	}

	if len(violation.AnnotationParameters()) > 0 {
		if constraintTemplate.Spec.CRD.Spec.Validation != nil {
			logger.Warn("Parameters already set with legacy annotations, overwriting the parameters using values from OPA Metadata")
		}
		constraintTemplate.Spec.CRD.Spec.Validation = &v1.Validation{
			OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
				Properties: violation.AnnotationParameters(),
				Type:       "object",
			},
		}
	}

	return &constraintTemplate
}

func getConstraintTemplatev1beta1(violation rego.Rego, logger *log.Entry) *v1beta1.ConstraintTemplate {
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
		logger.Warn("Parameters" + legacyMigrationMessage)
		constraintTemplate.Spec.CRD.Spec.Validation = &v1beta1.Validation{
			OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
				Properties: violation.GetOpenAPISchemaProperties(),
			},
		}
	}

	if len(violation.AnnotationParameters()) > 0 {
		if constraintTemplate.Spec.CRD.Spec.Validation != nil {
			logger.Warn("Parameters already set with legacy annotations, overwriting the parameters using values from OPA Metadata")
		}
		constraintTemplate.Spec.CRD.Spec.Validation = &v1beta1.Validation{
			OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
				Properties: violation.AnnotationParameters(),
			},
		}
	}

	return &constraintTemplate
}

func getConstraint(violation rego.Rego, logger *log.Entry) (*unstructured.Unstructured, error) {
	gvk := schema.GroupVersionKind{
		Group:   "constraints.gatekeeper.sh",
		Version: "v1beta1",
		Kind:    violation.Kind(),
	}

	var constraint unstructured.Unstructured
	constraint.SetGroupVersionKind(gvk)
	constraint.SetName(violation.Name())
	annotations := violation.Annotations()
	if annotations != nil {
		constraint.SetAnnotations(annotations)
	}
	labels := violation.Labels()
	if labels != nil {
		constraint.SetLabels(labels)
	}

	if violation.Enforcement() != "deny" {
		if err := unstructured.SetNestedField(constraint.Object, violation.Enforcement(), "spec", "enforcementAction"); err != nil {
			return nil, fmt.Errorf("set constraint enforcement: %w", err)
		}
	}

	// The dryrun flag overrides any enforcement action specified in the rego header.
	dryrun := viper.GetBool("dryrun")
	if dryrun {
		if err := unstructured.SetNestedField(constraint.Object, "dryrun", "spec", "enforcementAction"); err != nil {
			return nil, fmt.Errorf("set constraint dryrun: %w", err)
		}
	}

	matchers, err := violation.Matchers()
	if err != nil {
		return nil, fmt.Errorf("get matchers: %w", err)
	}

	if len(matchers.KindMatchers) > 0 {
		logger.Warn("Kind Matchers" + legacyMigrationMessage)
		if err := setKindMatcher(&constraint, matchers.KindMatchers); err != nil {
			return nil, fmt.Errorf("set kind matcher: %w", err)
		}
	}

	if len(matchers.MatchLabelsMatcher) > 0 {
		logger.Warn("Match Labels Matchers" + legacyMigrationMessage)
		if err := setMatchLabelsMatcher(&constraint, matchers.MatchLabelsMatcher); err != nil {
			return nil, fmt.Errorf("set match labels matcher: %w", err)
		}
	}

	if len(matchers.MatchExpressionsMatcher) > 0 {
		logger.Warn("Match Expressions Matchers" + legacyMigrationMessage)
		if err := setMatchExpressionsMatcher(&constraint, matchers.MatchExpressionsMatcher); err != nil {
			return nil, fmt.Errorf("set match expressions matcher: %w", err)
		}
	}

	if len(matchers.NamespaceMatcher) > 0 {
		logger.Warn("Namespace Matchers" + legacyMigrationMessage)
		if err := setNestedStringSlice(&constraint, matchers.NamespaceMatcher, "spec", "match", "namespaces"); err != nil {
			return nil, fmt.Errorf("set namespace matcher: %w", err)
		}
	}

	if len(matchers.ExcludedNamespaceMatcher) > 0 {
		logger.Warn("Excluded Namespace Matchers" + legacyMigrationMessage)
		if err := setNestedStringSlice(&constraint, matchers.ExcludedNamespaceMatcher, "spec", "match", "excludedNamespaces"); err != nil {
			return nil, fmt.Errorf("set namespace matcher: %w", err)
		}
	}

	metadataMatchers, err := violation.GetAnnotation("matchers")
	if err == nil {
		if len(matchers.KindMatchers) > 0 ||
			len(matchers.MatchLabelsMatcher) > 0 ||
			len(matchers.MatchExpressionsMatcher) > 0 ||
			len(matchers.NamespaceMatcher) > 0 ||
			len(matchers.ExcludedNamespaceMatcher) > 0 {
			logger.Warn("Overwriting matchers set with legacy annotations using matchers from OPA Metadata.")
		}

		if err := unstructured.SetNestedField(constraint.Object, metadataMatchers, "spec", "match"); err != nil {
			return nil, fmt.Errorf("set matchers from metadata annotation: %w", err)
		}
	}

	if viper.GetBool("partial-constraints") {
		if len(violation.Parameters()) > 0 {
			logger.Warn("Parameters" + legacyMigrationMessage)
			if err := addParametersToConstraintLegacy(&constraint, violation.Parameters()); err != nil {
				return nil, fmt.Errorf("add parameters %v to constraint: %w", violation.Parameters(), err)
			}
		}
		if len(violation.AnnotationParameters()) > 0 {
			if err := addParametersToConstraint(&constraint, violation.AnnotationParameters()); err != nil {
				return nil, fmt.Errorf("add parameters %v to constraint: %w", violation.AnnotationParameters(), err)
			}
		}
	}

	return &constraint, nil
}

func addParametersToConstraint(constraint *unstructured.Unstructured, parameters map[string]apiextensionsv1.JSONSchemaProps) error {
	params := make(map[string]any, len(parameters))
	for p := range parameters {
		params[p] = nil
	}
	if err := unstructured.SetNestedField(constraint.Object, params, "spec", "parameters"); err != nil {
		return fmt.Errorf("set parameters map: %w", err)
	}

	return nil
}

func addParametersToConstraintLegacy(constraint *unstructured.Unstructured, parameters []rego.Parameter) error {
	params := make(map[string]interface{}, len(parameters))
	for _, p := range parameters {
		params[p.Name] = nil
	}
	if err := unstructured.SetNestedField(constraint.Object, params, "spec", "parameters"); err != nil {
		return fmt.Errorf("set parameters map: %w", err)
	}

	return nil
}

func setKindMatcher(constraint *unstructured.Unstructured, kindMatchers rego.KindMatchers) error {
	if err := unstructured.SetNestedSlice(constraint.Object, kindMatchers.ToSpec(), "spec", "match", "kinds"); err != nil {
		return fmt.Errorf("set constraint kinds matchers: %w", err)
	}
	return nil
}

func setMatchLabelsMatcher(constraint *unstructured.Unstructured, matcher rego.MatchLabelsMatcher) error {
	if err := unstructured.SetNestedStringMap(constraint.Object, matcher, "spec", "match", "labelSelector", "matchLabels"); err != nil {
		return fmt.Errorf("set constraint labelSelector.matchLabels matchers: %w", err)
	}
	return nil
}

func setMatchExpressionsMatcher(constraint *unstructured.Unstructured, matcher []rego.MatchExpressionMatcher) error {
	marshaled, err := json.Marshal(matcher)
	if err != nil {
		return err
	}
	var unmarshaled []interface{}
	if err := json.Unmarshal(marshaled, &unmarshaled); err != nil {
		return err
	}
	return unstructured.SetNestedSlice(constraint.Object, unmarshaled, "spec", "match", "labelSelector", "matchExpressions")
}

func setNestedStringSlice(constraint *unstructured.Unstructured, slice []string, path ...string) error {
	var values []interface{}
	for _, s := range slice {
		values = append(values, interface{}(s))
	}
	return unstructured.SetNestedSlice(constraint.Object, values, path...)
}

func isValidEnforcementAction(action string) bool {
	for _, a := range []string{"deny", "dryrun", "warn"} {
		if a == action {
			return true
		}
	}

	return false
}
