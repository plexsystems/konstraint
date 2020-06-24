package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Constraint is a Gatekeeper constraint
type Constraint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
}

// NewCreateCommand creates a new create command
func NewCreateCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "create <dir>",
		Short: "Create Gatekeeper constraints from Rego policies",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreateCommand(args[0])
		},
	}

	return &cmd
}

func runCreateCommand(path string) error {
	policyContents, libraryContents, err := getRegoFiles(path)
	if err != nil {
		return fmt.Errorf("get rego files: %v", path)
	}

	for dir, contents := range policyContents {
		kind := filepath.Base(dir)
		kind = strings.ReplaceAll(kind, "-", " ")
		kind = strings.Title(kind)
		kind = strings.ReplaceAll(kind, " ", "")

		name := strings.ToLower(kind)

		constraintTemplate := getConstraintTemplate(name, kind, contents, libraryContents)
		constraintTemplateBytes, err := yaml.Marshal(&constraintTemplate)
		if err != nil {
			return fmt.Errorf("marshal constrainttemplate: %w", err)
		}

		err = ioutil.WriteFile(filepath.Join(dir, "template.yaml"), constraintTemplateBytes, os.ModePerm)
		if err != nil {
			return fmt.Errorf("writing template: %w", err)
		}

		constraint := getConstraint(kind)
		constraintBytes, err := yaml.Marshal(&constraint)
		if err != nil {
			return fmt.Errorf("marshal constraint: %w", err)
		}

		err = ioutil.WriteFile(filepath.Join(dir, "constraint.yaml"), constraintBytes, os.ModePerm)
		if err != nil {
			return fmt.Errorf("writing constraint: %w", err)
		}
	}

	return nil
}

func getConstraintTemplate(name string, kind string, policy string, libs []string) v1beta1.ConstraintTemplate {
	constraintTemplate := v1beta1.ConstraintTemplate{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "templates.gatekeeper.sh/v1beta1",
			Kind:       "ConstraintTemplate",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1beta1.ConstraintTemplateSpec{
			CRD: v1beta1.CRD{
				Spec: v1beta1.CRDSpec{
					Names: v1beta1.Names{
						Kind: kind,
					},
				},
			},
			Targets: []v1beta1.Target{
				{
					Target: "admission.k8s.gatekeeper.sh",
					Libs:   libs,
					Rego:   policy,
				},
			},
		},
	}

	return constraintTemplate
}

func getConstraint(kind string) Constraint {
	constraint := Constraint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "constraints.gatekeeper.sh/v1beta1",
			Kind:       kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: strings.ToLower(kind),
		},
	}

	return constraint
}

func getRegoFiles(path string) (map[string]string, []string, error) {
	var libraryContents []string
	policyContents := make(map[string]string)

	err := filepath.Walk(path, func(currentFilePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk path: %w", err)
		}

		if fileInfo.IsDir() && fileInfo.Name() == ".git" {
			return filepath.SkipDir
		}

		if fileInfo.IsDir() {
			return nil
		}

		if filepath.Ext(currentFilePath) != ".rego" || strings.HasSuffix(fileInfo.Name(), "_test.rego") {
			return nil
		}

		regoContents, err := ioutil.ReadFile(currentFilePath)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		if filepath.Base(filepath.Dir(currentFilePath)) == "lib" {
			libraryContents = append(libraryContents, string(regoContents))
		} else {
			policyContents[filepath.Dir(currentFilePath)] = string(regoContents)
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return policyContents, libraryContents, nil
}
