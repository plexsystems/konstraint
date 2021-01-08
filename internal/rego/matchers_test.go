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
		headerComments: comments,
	}

	expected := KindMatchers{
		{APIGroup: "core", Kind: "Pod"},
		{APIGroup: "apps", Kind: "Deployment"},
	}

	matchers, err := rego.Matchers()
	if err != nil {
		t.Fatal(err)
	}
	actual := matchers.KindMatchers

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected KindMatchers. expected %v, actual %v.", expected, actual)
	}
}

func TestGetMatchLabelsMatcher(t *testing.T) {
	comments := []string{
		"@matchlabels team=a app.kubernetes.io/name=test",
	}
	rego := Rego{
		headerComments: comments,
	}

	expected := MatchLabelsMatcher{
		"team":                   "a",
		"app.kubernetes.io/name": "test",
	}

	matchers, err := rego.Matchers()
	if err != nil {
		t.Fatal(err)
	}
	actual := matchers.MatchLabelsMatcher

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected MatchLabelMatcher. expected %v, actual %v.", expected, actual)
	}
}

func TestGetNamespacesMatcher(t *testing.T) {
	comments := []string{
		"@namespaces kube-system gatekeeper-system",
	}

	rego := Rego{
		headerComments: comments,
	}

	expected := NamespacesMatchers{
		"kube-system", "gatekeeper-system",
	}

	matchers, err := rego.Matchers()
	if err != nil {
		t.Fatal(err)
	}
	actual := matchers.NamespacesMatchers

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected NamespacesMatchers. expected %v, actual %v.", expected, actual)
	}
}

func TestGetExcludedNamespacesMatcher(t *testing.T) {
	comments := []string{
		"@excludednamespaces kube-system gatekeeper-system",
	}

	rego := Rego{
		headerComments: comments,
	}

	expected := ExcludedNamespacesMatchers{
		"kube-system", "gatekeeper-system",
	}

	matchers, err := rego.Matchers()
	if err != nil {
		t.Fatal(err)
	}
	actual := matchers.ExcludedNamespacesMatchers

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected ExcludedNamespacesMatchers. expected %v, actual %v.", expected, actual)
	}
}
