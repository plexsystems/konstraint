package commands

import (
	"testing"

	"github.com/plexsystems/konstraint/internal/rego"
)

func TestGetMatchersFromComments_NoKinds(t *testing.T) {
	policy := `package test
# Description
violation[msg] {
	false
}`

	regoFile, err := rego.NewFile("test.rego", policy)
	if err != nil {
		t.Fatal("new rego file", err)
	}

	actual, err := GetMatchersFromComments(regoFile.Comments)
	if err != nil {
		t.Fatal("get policy comment blocks:", err)
	}

	if len(actual.APIGroups) > 0 {
		t.Error("expected no APIGroups, but APIGroups were returned")
	}

	if len(actual.APIGroups) > 0 {
		t.Error("expected no Kinds, but Kinds were returned")
	}
}

func TestGetMatchersFromComments(t *testing.T) {
	policy := `package test
# First description
# @Kinds core/Pod apps/Deployment apps/DaemonSet
violation[msg] {
	false
}`

	regoFile, err := rego.NewFile("test.rego", policy)
	if err != nil {
		t.Fatal("new rego file", err)
	}

	actual, err := GetMatchersFromComments(regoFile.Comments)
	if err != nil {
		t.Fatal("get matchers:", err)
	}

	expectedAPIGroupCount := 2
	if len(actual.APIGroups) != expectedAPIGroupCount {
		t.Errorf("expected %v APIGroups to exist, but %v were found", expectedAPIGroupCount, len(actual.APIGroups))
	}

	expectedGroups := []string{"core", "apps"}
	for _, expectedGroup := range expectedGroups {
		if !contains(actual.APIGroups, expectedGroup) {
			t.Errorf("expected matcher to contain APIGroup '%v', but was not found.", expectedGroup)
		}
	}

	expectedKinds := []string{"Pod", "DaemonSet", "Deployment"}
	for _, expectedKind := range expectedKinds {
		if !contains(actual.Kinds, expectedKind) {
			t.Errorf("expected matcher to contain Kind '%v', but was not found.", expectedKind)
		}
	}
}
