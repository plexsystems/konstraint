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
# @Kinds core/Pod apps/Deployment
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

	libraryRegos := []string{`package lib.foo`, `package lib.bar`}

	policyFile, err := rego.NewFile("/foo/test-kind/src.rego", policyImportsFoo)
	if err != nil {
		t.Fatal("new rego file:", err)
	}

	var libraries []rego.File
	for key, library := range libraryRegos {
		libraryPath := fmt.Sprintf("/foo/lib/library-%v.rego", key)

		libraryFile, err := rego.NewFile(libraryPath, library)
		if err != nil {
			t.Fatal("new rego file:", err)
		}

		libraries = append(libraries, libraryFile)
	}

	actual := getConstraintTemplate(policyFile, libraries)
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
