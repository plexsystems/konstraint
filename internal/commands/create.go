package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/plexsystems/konstraint/internal/rego"

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
			if err := viper.BindPFlag("partial-constraints", cmd.PersistentFlags().Lookup("partial-constraints")); err != nil {
				return fmt.Errorf("bind partial-constraints flag: %w", err)
			}

			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runCreateCommand(path)
		},
	}

	cmd.PersistentFlags().StringP("output", "o", "", "Specify an output directory for the Gatekeeper resources")
	cmd.PersistentFlags().BoolP("dryrun", "d", false, "Sets the enforcement action of the constraints to dryrun, overriding the enforcement setting")
	cmd.PersistentFlags().Bool("skip-constraints", false, "Skip generation of constraints")
	cmd.PersistentFlags().String("constraint-template-version", "v1beta1", "Set the version of ConstraintTemplates")
	cmd.PersistentFlags().Bool("partial-constraints", false, "Generate partial Constraints for policies with parameters")

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
		var constraintTemplate any
		switch constraintTemplateVersion {
		case "v1":
			constraintTemplate = getConstraintTemplatev1(violation, logger)
		case "v1beta1":
			constraintTemplate = getConstraintTemplatev1beta1(violation, logger)
		default:
			return fmt.Errorf("unsupported API version for constrainttemplate: %s", constraintTemplateVersion)
		}

		constraintTemplateBytes, err := yaml.Marshal(constraintTemplate)
		if err != nil {
			return fmt.Errorf("marshal constrainttemplate: %w", err)
		}

		if err := os.WriteFile(filepath.Join(outputDir, templateFileName), constraintTemplateBytes, 0644); err != nil {
			return fmt.Errorf("writing template: %w", err)
		}

		if viper.GetBool("skip-constraints") || violation.SkipConstraint() {
			logger.Info("Skipping constraint generation due to configuration")
			continue
		}

		// Skip Constraint generation if there are parameters on the template.
		if !viper.GetBool("partial-constraints") && len(violation.AnnotationParameters()) > 0 {
			logger.Warn("Skipping constraint generation due to use of parameters")
			continue
		}

		constraint, err := getConstraint(violation, logger)
		if err != nil {
			return fmt.Errorf("get constraint: %w", err)
		}

		constraintBytes, err := yaml.Marshal(constraint)
		if err != nil {
			return fmt.Errorf("marshal constraint: %w", err)
		}

		if err := os.WriteFile(filepath.Join(outputDir, constraintFileName), constraintBytes, 0644); err != nil {
			return fmt.Errorf("writing constraint: %w", err)
		}
	}

	log.WithField("num_policies", len(violations)).Info("completed successfully")

	return nil
}

func getConstraintTemplatev1(violation rego.Rego, _ *log.Entry) *v1.ConstraintTemplate {
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

	if len(violation.AnnotationParameters()) > 0 {
		constraintTemplate.Spec.CRD.Spec.Validation = &v1.Validation{
			OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
				Properties: violation.AnnotationParameters(),
				Type:       "object",
			},
		}
	}

	return &constraintTemplate
}

func getConstraintTemplatev1beta1(violation rego.Rego, _ *log.Entry) *v1beta1.ConstraintTemplate {
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

	if len(violation.AnnotationParameters()) > 0 {
		constraintTemplate.Spec.CRD.Spec.Validation = &v1beta1.Validation{
			OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
				Properties: violation.AnnotationParameters(),
			},
		}
	}

	return &constraintTemplate
}

func getConstraint(violation rego.Rego, _ *log.Entry) (*unstructured.Unstructured, error) {
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

	metadataMatchers, ok := violation.GetAnnotation("matchers")
	if ok {
		if err := unstructured.SetNestedField(constraint.Object, metadataMatchers, "spec", "match"); err != nil {
			return nil, fmt.Errorf("set matchers from metadata annotation: %w", err)
		}
	}

	if viper.GetBool("partial-constraints") {
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

func isValidEnforcementAction(action string) bool {
	for _, a := range []string{"deny", "dryrun", "warn"} {
		if a == action {
			return true
		}
	}

	return false
}
