package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewTemplateCommand creates a new template command
func NewTemplateCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "template <rego file>",
		Short: "Create ConstraintTemplate CRD from a Rego policy",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return runTemplateCommand(args[0])
		},
	}

	return &cmd
}

func runTemplateCommand(path string) error {
	regoFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open path: %v", path)
	}

	regoContents, err := ioutil.ReadAll(regoFile)
	if err != nil {
		return fmt.Errorf("unable to read file: %v", regoFile)
	}

	regoAst := ast.MustParseModule(string(regoContents))
	if regoAst == nil {
		return fmt.Errorf("unable to parse rego file")
	}

	const violationText = `violation[{"msg": msg}]`
	violationRego := strings.ReplaceAll(string(regoContents), "deny[msg]", violationText)

	regoPackage := strings.Split(string(regoAst.Package.Location.Text), " ")[1]

	constraintTemplate := v1beta1.ConstraintTemplate{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "templates.gatekeeper.sh/v1beta1",
			Kind:       "ConstraintTemplate",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: regoPackage,
		},
		Spec: v1beta1.ConstraintTemplateSpec{
			CRD: v1beta1.CRD{
				Spec: v1beta1.CRDSpec{
					Names: v1beta1.Names{
						Kind: regoPackage,
					},
				},
			},
			Targets: []v1beta1.Target{
				{
					Rego: violationRego,
				},
			},
		},
	}

	templateFile, err := yaml.Marshal(&constraintTemplate)
	if err != nil {
		return fmt.Errorf("marshal constraint: %w", err)
	}

	err = ioutil.WriteFile("template.yaml", templateFile, os.ModePerm)
	if err != nil {
		return fmt.Errorf("writing yaml: %w", err)
	}

	return nil
}
