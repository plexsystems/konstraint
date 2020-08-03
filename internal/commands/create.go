package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/plexsystems/konstraint/internal/rego"

	"github.com/ghodss/yaml"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	"github.com/open-policy-agent/gatekeeper/apis/config/v1alpha1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
				return fmt.Errorf("bind ouput flag: %w", err)
			}

			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			return runCreateCommand(path)
		},
	}

	cmd.PersistentFlags().StringP("output", "o", "", "Specify an output directory for the Gatekeeper resources")
	cmd.PersistentFlags().BoolP("dryrun", "d", false, "Sets the enforcement action of the constraints to dryrun")

	return &cmd
}

type SyncResource struct {
	Group   string
	Version string
	Kind    string
}

func runCreateCommand(path string) error {
	policies, err := rego.GetFilesWithRule(path, "violation")
	if err != nil {
		return fmt.Errorf("get policies: %w", err)
	}

	libraryPath, err := getLibraryPath(path)
	if err != nil {
		return fmt.Errorf("get library path: %w", err)
	}

	libraries, err := rego.GetFiles(libraryPath)
	if err != nil {
		return fmt.Errorf("get libraries: %w", err)
	}

	for l := range libraries {
		libraries[l].Contents = getRegoWithoutComments(libraries[l].Contents)
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
		policyDir := filepath.Dir(policy.FilePath)

		if outputFlag == "" {
			outputDir = policyDir
		} else {
			templateFileName = fmt.Sprintf("template_%s.yaml", GetKindFromPath(policy.FilePath))
			constraintFileName = fmt.Sprintf("constraint_%s.yaml", GetKindFromPath(policy.FilePath))
		}

		importedLibraries := getImportedLibraries(policy, libraries)
		var librariesContents []string
		for _, library := range importedLibraries {
			librariesContents = append(librariesContents, getRegoWithoutComments(library.Contents))
		}

		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			err := os.MkdirAll(outputDir, os.ModePerm)
			if err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}
		}

		constraintTemplate := getConstraintTemplate(policy, librariesContents)
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

	syncResources, err := getSyncResources(policies)
	if err != nil {
		return fmt.Errorf("get sync resources: %w", err)
	}

	config := getConfig(syncResources)
	configBytes, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("marshal constraint: %w", err)
	}

	if err := ioutil.WriteFile(filepath.Join(outputDir, "config.yaml"), configBytes, os.ModePerm); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

func getConfig(syncResources []SyncResource) v1alpha1.Config {
	var syncOnlyEntries []v1alpha1.SyncOnlyEntry
	for _, syncResource := range syncResources {
		syncOnlyEntry := v1alpha1.SyncOnlyEntry{
			Version: syncResource.Version,
			Kind:    syncResource.Kind,
		}

		syncOnlyEntries = append(syncOnlyEntries, syncOnlyEntry)
	}

	configSpec := v1alpha1.ConfigSpec{
		Sync: v1alpha1.Sync{
			SyncOnly: syncOnlyEntries,
		},
	}

	config := v1alpha1.Config{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "config.gatekeeper.sh/v1alpha1",
			Kind:       "Config",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: "gatekeeper-system",
		},
		Spec: configSpec,
	}

	return config
}

func getSyncResources(files []rego.File) ([]SyncResource, error) {
	var syncResources []SyncResource
	for _, file := range files {
		tokens := strings.Split(file.Contents, " ")
		for _, token := range tokens {
			if strings.HasPrefix(token, "data.inventory.namespace") {
				re, err := regexp.Compile(`\[(.*?)\]`)
				if err != nil {
					return nil, fmt.Errorf("compile inventory regex: %w", err)
				}

				inventorySegments := re.FindAllString(token, -1)
				version := inventorySegments[1]
				version = strings.ReplaceAll(version, "[", "")
				version = strings.ReplaceAll(version, "]", "")
				version = strings.ReplaceAll(version, "\"", "")

				kind := inventorySegments[2]
				kind = strings.ReplaceAll(kind, "[", "")
				kind = strings.ReplaceAll(kind, "]", "")
				kind = strings.ReplaceAll(kind, "\"", "")

				syncResource := SyncResource{
					Version: version,
					Kind:    kind,
				}

				syncResources = append(syncResources, syncResource)
			}
		}
	}

	return syncResources, nil
}

func getConstraintTemplate(policy rego.File, libraries []string) v1beta1.ConstraintTemplate {
	kind := GetKindFromPath(policy.FilePath)

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
					Libs:   libraries,
					Rego:   getRegoWithoutComments(policy.Contents),
				},
			},
		},
	}

	return constraintTemplate
}

func getConstraint(policy rego.File) (unstructured.Unstructured, error) {
	kind := GetKindFromPath(policy.FilePath)
	constraint := unstructured.Unstructured{}
	constraint.SetName(strings.ToLower(kind))
	constraint.SetGroupVersionKind(schema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: kind})

	dryrun := viper.GetBool("dryrun")
	if dryrun {
		if err := unstructured.SetNestedField(constraint.Object, "dryrun", "spec", "enforcementAction"); err != nil {
			return unstructured.Unstructured{}, fmt.Errorf("set constraint dryrun: %w", err)
		}
	}

	matchers := GetMatchersFromComments(policy.Comments)
	if len(matchers.KindMatchers) == 0 {
		return constraint, nil
	}

	var kinds []interface{}
	var apiGroups []interface{}
	for _, kindMatcher := range matchers.KindMatchers {
		kinds = append(kinds, kindMatcher.Kind)
	}

	for _, kindMatcher := range matchers.KindMatchers {
		apiGroup := kindMatcher.APIGroup
		if kindMatcher.APIGroup == "core" {
			apiGroup = ""
		}

		var exists bool
		for _, addedGroup := range apiGroups {
			if apiGroup == addedGroup {
				exists = true
			}
		}
		if !exists {
			apiGroups = append(apiGroups, apiGroup)
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

func getLibraryPath(path string) (string, error) {
	libraryFolderNames := []string{"lib", "libs", "util", "utils"}

	var libraryPath string
	err := filepath.Walk(path, func(currentFilePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk path: %w", err)
		}

		if fileInfo.IsDir() && fileInfo.Name() == ".git" {
			return filepath.SkipDir
		}

		if fileInfo.IsDir() && contains(libraryFolderNames, fileInfo.Name()) {
			libraryPath = currentFilePath
			return nil
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	return libraryPath, nil
}

func getImportedLibraries(file rego.File, allLibraries []rego.File) []rego.File {
	var importedLibraries []rego.File
	for _, importedPackage := range file.ImportPackages {
		for _, library := range allLibraries {
			if library.PackageName == importedPackage {
				importedLibraries = append(importedLibraries, library)
			}
		}
	}

	for _, library := range importedLibraries {
		importedLibraries = append(importedLibraries, getImportedLibraries(library, allLibraries)...)
	}

	importedLibraries = getUniqueRegoFiles(importedLibraries)
	return importedLibraries
}

func getUniqueRegoFiles(files []rego.File) []rego.File {
	var uniqueFiles []rego.File
	for _, file := range files {
		var seen bool
		for _, uniqueFile := range uniqueFiles {
			if file.PackageName == uniqueFile.PackageName {
				seen = true
				break
			}
		}

		if !seen {
			uniqueFiles = append(uniqueFiles, file)
		}
	}

	return uniqueFiles
}
