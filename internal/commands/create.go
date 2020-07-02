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

type regoFile struct {
	filePath       string
	packageName    string
	importPackages []string
	contents       string
}

func newRegoFile(filePath string, contents string) (regoFile, error) {
	module, err := ast.ParseModule(filePath, contents)
	if err != nil {
		return regoFile{}, fmt.Errorf("parse module: %w", err)
	}

	var importPackages []string
	for i := range module.Imports {
		importPackages = append(importPackages, module.Imports[i].Path.String())
	}

	regoFile := regoFile{
		filePath:       filePath,
		packageName:    module.Package.Path.String(),
		importPackages: importPackages,
		contents:       contents,
	}

	return regoFile, nil
}

func newCreateCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "create <dir>",
		Short: "Create Gatekeeper constraints from Rego policies",

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

	cmd.PersistentFlags().StringP("output", "o", "", "Specify an output directory for the Gatekeeper resources")
	viper.BindPFlag("output", cmd.PersistentFlags().Lookup("output"))
	cmd.PersistentFlags().BoolP("dryrun", "d", false, "Sets the enforcement action of the constraints to dryrun")
	viper.BindPFlag("dryrun", cmd.PersistentFlags().Lookup("dryrun"))

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

	policies, err := loadRegoFiles(policyFilePaths)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	libraries, err := loadRegoFiles(libraryFilePaths)
	if err != nil {
		return fmt.Errorf("load libraries: %w", err)
	}

	var templateFileName, constraintFileName, outputDir string
	outputFlag := viper.GetString("output")
	if outputFlag == "" {
		templateFileName = "template.yaml"
		constraintFileName = "constraint.yaml"
	} else {
		outputDir = outputFlag
	}

	for _, policy := range policies {
		policyDir := filepath.Dir(policy.filePath)

		if outputFlag == "" {
			outputDir = policyDir
		} else {
			templateFileName = fmt.Sprintf("template_%s.yaml", getKindFromPath(policy.filePath))
			constraintFileName = fmt.Sprintf("constraint_%s.yaml", getKindFromPath(policy.filePath))
		}

		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			err := os.MkdirAll(outputDir, os.ModePerm)
			if err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}
		}

		constraintTemplate := getConstraintTemplate(policy, libraries)
		constraintTemplateBytes, err := yaml.Marshal(&constraintTemplate)
		if err != nil {
			return fmt.Errorf("marshal constrainttemplate: %w", err)
		}

		err = ioutil.WriteFile(filepath.Join(outputDir, templateFileName), constraintTemplateBytes, os.ModePerm)
		if err != nil {
			return fmt.Errorf("writing template: %w", err)
		}

		constraint, err := getConstraint(policy)
		if err != nil {
			return fmt.Errorf("get constraint: %w", err)
		}

		constraintBytes, err := yaml.Marshal(&constraint)
		if err != nil {
			return fmt.Errorf("marshal constraint: %w", err)
		}

		err = ioutil.WriteFile(filepath.Join(outputDir, constraintFileName), constraintBytes, os.ModePerm)
		if err != nil {
			return fmt.Errorf("writing constraint: %w", err)
		}
	}

	return nil
}

func getConstraintTemplate(policy regoFile, libraries []regoFile) v1beta1.ConstraintTemplate {
	var libs []string
	for _, importPackage := range policy.importPackages {
		for _, library := range libraries {
			if importPackage == library.packageName {
				libs = append(libs, library.contents)
			}
		}
	}

	kind := getKindFromPath(policy.filePath)

	constraintTemplate := v1beta1.ConstraintTemplate{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "templates.gatekeeper.sh/v1beta1",
			Kind:       "ConstraintTemplate",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: strings.ToLower(kind),
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
					Rego:   policy.contents,
				},
			},
		},
	}

	return constraintTemplate
}

func getConstraint(policy regoFile) (unstructured.Unstructured, error) {
	kind := getKindFromPath(policy.filePath)
	constraint := unstructured.Unstructured{}
	constraint.SetName(strings.ToLower(kind))
	constraint.SetGroupVersionKind(schema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: kind})

	policyCommentBlocks, err := getPolicyCommentBlocks(policy.contents)
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

	dryrun := viper.GetBool("dryrun")
	if dryrun {
		if err := unstructured.SetNestedField(constraint.Object, "dryrun", "spec", "enforcementAction"); err != nil {
			return unstructured.Unstructured{}, fmt.Errorf("set constraint dryrun: %w", err)
		}
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

func loadRegoFiles(filePaths []string) ([]regoFile, error) {
	var regoFiles []regoFile
	for _, filePath := range filePaths {
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read policy file: %w", err)
		}

		regoFile, err := newRegoFile(filePath, string(data))
		if err != nil {
			return nil, fmt.Errorf("new rego file: %w", err)
		}

		regoFiles = append(regoFiles, regoFile)
	}

	return regoFiles, nil
}

func getKindFromPath(path string) string {
	kind := filepath.Base(filepath.Dir(path))
	kind = strings.ReplaceAll(kind, "-", " ")
	kind = strings.Title(kind)
	kind = strings.ReplaceAll(kind, " ", "")

	return kind
}
