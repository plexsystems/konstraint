package commands

import "testing"

func TestGetConstraint_NoKinds_ReturnsEmptyMatcher(t *testing.T) {
	var emptyPolicy []byte

	actual, err := getConstraint("TestKind", emptyPolicy)
	if err != nil {
		t.Fatal("get constraint:", err)
	}

	if _, exists := actual.Object["spec"]; exists {
		t.Errorf("expected no spec section, but one existed.")
	}
}

func TestGetConstraint_KindsInComment_ReturnsSpecMatchingKinds(t *testing.T) {
	policyWithKinds := `
# Description
# @Kinds core/Pod apps/Deployment`

	actual, err := getConstraint("TestKind", []byte(policyWithKinds))
	if err != nil {
		t.Fatal("get constraint:", err)
	}

	if _, exists := actual.Object["spec"]; !exists {
		t.Errorf("expected spec section, but one did not exist.")
	}
}

func TestGetKindFromPath(t *testing.T) {
	path := "/path/to/rego/container-resource-limits/something.rego"

	expected := "ContainerResourceLimits"
	actual := getKindFromPath(path)

	if actual != expected {
		t.Errorf("expected Kind of %v, but got %v", expected, actual)
	}
}
