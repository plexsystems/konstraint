package rego

import "testing"

func TestGetKindFromPath(t *testing.T) {
	regoFile := File{
		FilePath: "/path/to/rego/container-resource-limits/something.rego",
	}

	expected := "ContainerResourceLimits"
	actual := regoFile.Kind()

	if actual != expected {
		t.Errorf("expected Kind of %v, but got %v", expected, actual)
	}
}
