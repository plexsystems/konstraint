package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
			if err := viper.BindPFlag("ignore", cmd.Flags().Lookup("ignore")); err != nil {
				return fmt.Errorf("bind ignore flag: %w", err)
			}

			if err := viper.BindPFlag("lib", cmd.Flags().Lookup("lib")); err != nil {
				return fmt.Errorf("bind lib flag: %w", err)
			}

			return runCreateCommand(args[0])
		},
	}

	return &cmd
}

func runCreateCommand(path string) error {
	regoFilePaths, err := getRegoFilePaths(path)
	if err != nil {
		return fmt.Errorf("get rego files: %w", err)
	}

	var libraryFilePaths []string
	var policyFilePaths []string
	for _, regoFilePath := range regoFilePaths {
		if filepath.Base(filepath.Dir(regoFilePath)) != viper.GetString("lib") {
			policyFilePaths = append(policyFilePaths, regoFilePath)
		} else {
			libraryFilePaths = append(libraryFilePaths, regoFilePath)
		}
	}

	var libraryFileContents []string
	for _, libraryFilePath := range libraryFilePaths {
		libraryFileBytes, err := ioutil.ReadFile(libraryFilePath)
		if err != nil {
			return fmt.Errorf("read library file: %w", err)
		}

		libraryFileContents = append(libraryFileContents, string(libraryFileBytes))
	}

	for _, policyFilePath := range policyFilePaths {
		kind := filepath.Base(filepath.Dir(policyFilePath))
		kind = strings.ReplaceAll(kind, "-", " ")
		kind = strings.Title(kind)
		kind = strings.ReplaceAll(kind, " ", "")

		name := strings.ToLower(kind)

		policyDirectory := filepath.Dir(policyFilePath)

		policyFileBytes, err := ioutil.ReadFile(policyFilePath)
		if err != nil {
			return fmt.Errorf("read policy file: %w", err)
		}

		constraintTemplate := getConstraintTemplate(name, kind, string(policyFileBytes), libraryFileContents)
		constraintTemplateBytes, err := yaml.Marshal(&constraintTemplate)
		if err != nil {
			return fmt.Errorf("marshal constrainttemplate: %w", err)
		}

		err = ioutil.WriteFile(filepath.Join(policyDirectory, "template.yaml"), constraintTemplateBytes, os.ModePerm)
		if err != nil {
			return fmt.Errorf("writing template: %w", err)
		}

		constraint := getConstraint(kind)
		constraintBytes, err := yaml.Marshal(&constraint)
		if err != nil {
			return fmt.Errorf("marshal constraint: %w", err)
		}

		err = ioutil.WriteFile(filepath.Join(policyDirectory, "constraint.yaml"), constraintBytes, os.ModePerm)
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

func getRegoFilePaths(path string) ([]string, error) {
	ignoreRegex, err := regexp.Compile(viper.GetString("ignore"))
	if err != nil {
		return nil, fmt.Errorf("compile regex: %w", err)
	}

	var regoFilePaths []string
	err = filepath.Walk(path, func(currentFilePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk path: %w", err)
		}

		if fileInfo.IsDir() && fileInfo.Name() == ".git" {
			return filepath.SkipDir
		}

		if fileInfo.IsDir() && ignoreRegex.MatchString(currentFilePath) {
			return filepath.SkipDir
		}

		if ignoreRegex.MatchString(currentFilePath) {
			return nil
		}

		if filepath.Ext(currentFilePath) != ".rego" || strings.HasSuffix(fileInfo.Name(), "_test.rego") {
			return nil
		}

		regoFilePaths = append(regoFilePaths, currentFilePath)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return regoFilePaths, nil
}
