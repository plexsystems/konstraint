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

	actual := GetMatchersFromComments(regoFile.Comments)
	if len(actual.KindMatchers) > 0 {
		t.Error("expected no Kind matchers, but matchers were returned")
	}
}

func TestGetMatchersFromComments_Kinds(t *testing.T) {
	policy := `package test
# First description
# @kinds core/Pod apps/Deployment apps/DaemonSet
violation[msg] {
	false
}`

	regoFile, err := rego.NewFile("test.rego", policy)
	if err != nil {
		t.Fatal("new rego file", err)
	}

	actual := GetMatchersFromComments(regoFile.Comments)

	expectedMatcherCount := 3
	if len(actual.KindMatchers) != expectedMatcherCount {
		t.Errorf("expected %v matchers to exist, but %v were found", expectedMatcherCount, len(actual.KindMatchers))
	}

	expectedGroups := []string{"core", "apps", "apps"}
	for g, kindMatcher := range actual.KindMatchers {
		if kindMatcher.APIGroup != expectedGroups[g] {
			t.Errorf("expected group to be %v, but was %v", expectedGroups[g], kindMatcher.APIGroup)
		}
	}

	expectedKinds := []string{"Pod", "Deployment", "DaemonSet"}
	for k, kindMatcher := range actual.KindMatchers {
		if kindMatcher.Kind != expectedKinds[k] {
			t.Errorf("expected kind to be %v, but was %v", expectedKinds[k], kindMatcher.Kind)
		}
	}
}
