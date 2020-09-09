package rego

import (
	"reflect"
	"testing"
)

func TestGetKindMatchers(t *testing.T) {
	comments := []string{
		"@kinds core/Pod apps/Deployment",
	}
	rego := Rego{
		comments: comments,
	}

	expected := []KindMatcher{
		{APIGroup: "core", Kind: "Pod"},
		{APIGroup: "apps", Kind: "Deployment"},
	}

	actual := rego.Matchers().KindMatchers

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected KindMatchers. expected %v, actual %v.", expected, actual)
	}
}
