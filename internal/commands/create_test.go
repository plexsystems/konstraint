package commands

import (
	"fmt"
	"testing"

	"github.com/plexsystems/konstraint/internal/rego"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGetConstraint_NoKinds_ReturnsEmptyMatcher(t *testing.T) {
	policy := `package test
# Description
rule[msg] { msg = true }`

	parsedPolicy, err := rego.NewFile("test.rego", policy)
	if err != nil {
		t.Fatal("new rego file:", err)
	}

	actual, err := getConstraint(parsedPolicy)
	if err != nil {
		t.Fatal("get constraint:", err)
	}

	if _, exists := actual.Object["spec"]; exists {
		t.Errorf("expected no spec section, but one existed.")
	}
}

func TestGetConstraint_KindsInComment_ReturnsKinds(t *testing.T) {
	policy := `package test
# Description
# @kinds core/Pod apps/Deployment
rule[msg] { msg = true }`

	rego, err := rego.NewFile("test.rego", policy)
	if err != nil {
		t.Fatal("load policy rego file:", err)
	}

	actual, err := getConstraint(rego)
	if err != nil {
		t.Fatal("get constraint:", err)
	}

	kindMatchers, err := getConstraintKindMatchers(actual)
	if err != nil {
		t.Fatal("get constraint kind matchers:", err)
	}

	if len(kindMatchers) == 0 {
		t.Errorf("expected kind matcher to exist, but none were found")
	}

	expectedGroups := []string{"", "apps"}
	for _, expectedGroup := range expectedGroups {
		if !contains(kindMatchers[0].apiGroups, expectedGroup) {
			t.Errorf("expected apiGroup matcher to contain '%v', but was not found.", expectedGroup)
		}
	}

	expectedKinds := []string{"Pod", "Deployment"}
	for _, expectedKind := range expectedKinds {
		if !contains(kindMatchers[0].kinds, expectedKind) {
			t.Errorf("expected kind matcher to contain '%v', but was not found.", expectedKind)
		}
	}
}

func TestGetConstraintTemplate_CorrectLibrariesImported(t *testing.T) {
	policyImportsFoo := `package test

import data.lib.foo
rule[msg] { msg = true }`

	policyFile, err := rego.NewFile("/foo/test-kind/src.rego", policyImportsFoo)
	if err != nil {
		t.Fatal("new rego file:", err)
	}

	libraryRegos := []string{`package lib.foo`, `package lib.bar`}
	var libraries []rego.File
	for i, libraryRego := range libraryRegos {
		lib, err := rego.NewFile(fmt.Sprintf("lib.%d.rego", i), libraryRego)
		if err != nil {
			t.Fatal("create library from rego")
		}

		libraries = append(libraries, lib)
	}

	var librariesContents []string
	importedLibraries := getImportedLibraries(policyFile, libraries)
	for _, library := range importedLibraries {
		librariesContents = append(librariesContents, getRegoWithoutComments(library.Contents))
	}

	actual := getConstraintTemplate(policyFile, librariesContents)
	if err != nil {
		t.Fatal("get constraint:", err)
	}

	if len(actual.Spec.Targets) == 0 {
		t.Errorf("expected target to exist, but none were found")
	}

	actualLibraryCount := len(actual.Spec.Targets[0].Libs)
	if actualLibraryCount != 1 {
		t.Errorf("expected 1 library to be added, but found %v", actualLibraryCount)
	}
}

func TestRecursiveLibraryImport(t *testing.T) {
	policyImportsLibA := `package test
import data.lib.a`

	libFiles := []struct {
		path     string
		contents string
	}{
		{path: "lib_a.rego", contents: "package lib.a\nimport data.lib.b"},
		{path: "lib_b.rego", contents: "package lib.b"},
	}

	policy, err := rego.NewFile("test.rego", policyImportsLibA)
	if err != nil {
		t.Fatal("new policy file", err)
	}

	var libs []rego.File
	for _, libFile := range libFiles {
		lib, err := rego.NewFile(libFile.path, libFile.contents)
		if err != nil {
			t.Fatal("new library file", err)
		}
		libs = append(libs, lib)
	}

	importedLibraries := getImportedLibraries(policy, libs)
	if len(importedLibraries) != 2 {
		t.Error("recursive library import failed")
	}
}

func TestGetKindFromPath(t *testing.T) {
	path := "/path/to/rego/container-resource-limits/something.rego"

	expected := "ContainerResourceLimits"
	actual := GetKindFromPath(path)

	if actual != expected {
		t.Errorf("expected Kind of %v, but got %v", expected, actual)
	}
}

// Helpers to extract the collection of
// apiGroup and kind matchers in a Constraint
type kindMatcher struct {
	apiGroups []string
	kinds     []string
}

func getConstraintKindMatchers(constraint unstructured.Unstructured) ([]kindMatcher, error) {
	kindConfigs, exists, err := unstructured.NestedSlice(constraint.Object, "spec", "match", "kinds")
	if !exists {
		return nil, fmt.Errorf("kind config did not exist")
	} else if err != nil {
		return nil, fmt.Errorf("getting kind config: %w", err)
	}

	var kindMatchers []kindMatcher
	for _, kindConfig := range kindConfigs {
		currentKindConfig := kindConfig.(map[string]interface{})
		apiGroups, exists, err := unstructured.NestedStringSlice(currentKindConfig, "apiGroups")
		if !exists {
			return nil, fmt.Errorf("apiGroups matcher did not exist")
		} else if err != nil {
			return nil, fmt.Errorf("getting apiGroups matchers: %w", err)
		}

		kinds, exists, err := unstructured.NestedStringSlice(currentKindConfig, "kinds")
		if !exists {
			return nil, fmt.Errorf("kinds matcher did not exist")
		} else if err != nil {
			return nil, fmt.Errorf("getting kinds matchers: %w", err)
		}

		kindMatcher := kindMatcher{
			apiGroups: apiGroups,
			kinds:     kinds,
		}

		kindMatchers = append(kindMatchers, kindMatcher)
	}

	return kindMatchers, nil
}
