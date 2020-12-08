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

func TestGetMatchLabelsMatcher(t *testing.T) {
	comments := []string{
		"@matchlabels team=a app.kubernetes.io/name=test",
	}
	rego := Rego{
		comments: comments,
	}

	expected := MatchLabelsMatcher{
		"team":                   "a",
		"app.kubernetes.io/name": "test",
	}

	actual := rego.Matchers().MatchLabelsMatcher

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected MatchLabelMatcher. expected %v, actual %v.", expected, actual)
	}
}
