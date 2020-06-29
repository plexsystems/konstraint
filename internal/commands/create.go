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
	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type regoPolicy struct {
	path      string
	policy    *ast.Module
	libraries []string
}

type regoLibrary struct {
	path   string
	policy *ast.Module
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

			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runCreateCommand(path)
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

	policies, err := parsePolicies(policyFilePaths, libraryFilePaths)
	if err != nil {
		return fmt.Errorf("parsing policies: %s", err)
	}

	for _, policy := range policies {
		kind := getKindFromPath(policy.path)
		name := strings.ToLower(kind)

		policyDirectory := filepath.Dir(policy.path)

		policyFileBytes, err := ioutil.ReadFile(policy.path)
		if err != nil {
			return fmt.Errorf("read policy file: %w", err)
		}

		constraintTemplate := getConstraintTemplate(name, kind, string(policyFileBytes), policy.libraries)
		constraintTemplateBytes, err := yaml.Marshal(&constraintTemplate)
		if err != nil {
			return fmt.Errorf("marshal constrainttemplate: %w", err)
		}

		err = ioutil.WriteFile(filepath.Join(policyDirectory, "template.yaml"), constraintTemplateBytes, os.ModePerm)
		if err != nil {
			return fmt.Errorf("writing template: %w", err)
		}

		constraint, err := getConstraint(kind, policyFileBytes)
		if err != nil {
			return fmt.Errorf("get constraint: %w", err)
		}

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

func getConstraint(kind string, policy []byte) (unstructured.Unstructured, error) {
	constraint := unstructured.Unstructured{}
	constraint.SetName(strings.ToLower(kind))
	constraint.SetGroupVersionKind(schema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: kind})

	policyCommentBlocks, err := getPolicyCommentBlocks(policy)
	if err != nil {
		return unstructured.Unstructured{}, fmt.Errorf("get policy comment blocks: %w", err)
	}

	if len(policyCommentBlocks) == 0 {
		return constraint, nil
	}

	var kinds []interface{}
	var apiGroups []interface{}
	for _, policyCommentBlock := range policyCommentBlocks {
		for _, policyKind := range policyCommentBlock.Kinds {
			kinds = append(kinds, policyKind)
		}

		for _, policyAPIGroup := range policyCommentBlock.APIGroups {
			// The core API group is represented as a blank string in YAML files
			if policyAPIGroup == "core" {
				policyAPIGroup = ""
			}

			apiGroups = append(apiGroups, policyAPIGroup)
		}
	}

	constraintMatcher := map[string]interface{}{
		"apiGroups": apiGroups,
		"kinds":     kinds,
	}

	if err := unstructured.SetNestedSlice(constraint.Object, []interface{}{constraintMatcher}, "spec", "match", "kinds"); err != nil {
		return unstructured.Unstructured{}, fmt.Errorf("set constraint matchers: %w", err)
	}

	return constraint, nil
}

func getRegoFilePaths(path string) ([]string, error) {
	ignoreRegex, err := regexp.Compile(viper.GetString("ignore"))
	if err != nil {
		return nil, fmt.Errorf("compile ignore regex: %w", err)
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

func parsePolicies(policyPaths []string, libraryPaths []string) ([]*regoPolicy, error) {
	var policies []*regoPolicy
	var libraries []*regoLibrary

	// Load the policies and libraries into memory
	for _, file := range policyPaths {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, err
		}
		policy, err := ast.ParseModule("", string(data))
		if err != nil {
			return nil, err
		}
		policies = append(policies, &regoPolicy{path: file, policy: policy})
	}

	for _, file := range libraryPaths {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, err
		}
		library, err := ast.ParseModule("", string(data))
		if err != nil {
			return nil, err
		}
		libraries = append(libraries, &regoLibrary{path: file, policy: library})
	}

	// Match each policy's imports to those available
	for _, p := range policies {
		if len(p.policy.Imports) > 0 {
			for _, i := range p.policy.Imports {
				library := getLibrary(libraries, i.Path.String())
				if library == nil {
					return nil, fmt.Errorf("imported library %s not found", i.Path.String())
				}

				// We read the file again from disk to perserve the formatting of the policy
				// The OPA parser removes a lot of the nice syntax sugar that makes it easier for us to read
				// ---
				// We just read the library a few milliseconds ago, assuming errors won't happen on the second read
				data, _ := ioutil.ReadFile(library.path)
				p.libraries = append(p.libraries, string(data))
			}
		}
	}

	return policies, nil
}

func getLibrary(libraries []*regoLibrary, path string) *regoLibrary {
	for _, library := range libraries {
		if library.policy.Package.Path.String() == path {
			return library
		}
	}
	return nil
}

func getKindFromPath(path string) string {
	kind := filepath.Base(filepath.Dir(path))
	kind = strings.ReplaceAll(kind, "-", " ")
	kind = strings.Title(kind)
	kind = strings.ReplaceAll(kind, " ", "")

	return kind
}
