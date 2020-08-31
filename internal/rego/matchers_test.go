package rego

import (
	"reflect"
	"testing"
)

func TestGetKindMatchers(t *testing.T) {
	line := `@kinds core/Pod apps/Deployment`
	expected := []KindMatcher{
		{APIGroup: "core", Kind: "Pod"},
		{APIGroup: "apps", Kind: "Deployment"},
	}

	actual := getKindMatchers(line)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Unexpected KindMatchers. expected %v, actual %v.", expected, actual)
	}
}
