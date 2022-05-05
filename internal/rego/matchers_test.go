package rego

import (
	"reflect"
	"testing"
)

func TestGetKindMatchers(t *testing.T) {
	comments := []string{
		"@kinds core/Pod apps/Deployment",
		"@kinds apps/StatefulSet",
	}
	rego := Rego{
		headerComments: comments,
	}

	expected := KindMatchers{
		{APIGroup: "core", Kind: "Pod"},
		{APIGroup: "apps", Kind: "Deployment"},
		{APIGroup: "apps", Kind: "StatefulSet"},
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

func TestGetMatchExpressionsMatcher(t *testing.T) {
	testCases := []struct {
		name      string
		comments  []string
		expected  []MatchExpressionMatcher
		wantError bool
	}{
		{
			name: "Empty",
		},
		{
			name:     "Single",
			comments: []string{"@matchExpression foo In bar,baz"},
			expected: []MatchExpressionMatcher{
				{Key: "foo", Operator: "In", Values: []string{"bar", "baz"}},
			},
		},
		{
			name: "DoubleWithUnrelated",
			comments: []string{
				"@matchExpression foo In bar,baz",
				"@matchExpression doggos Exists",
				"unrelated comment",
			},
			expected: []MatchExpressionMatcher{
				{Key: "foo", Operator: "In", Values: []string{"bar", "baz"}},
				{Key: "doggos", Operator: "Exists"},
			},
		},
		{
			name: "TooFewParams",
			comments: []string{
				"@matchExpression foo",
			},
			wantError: true,
		},
		{
			name: "TooManyParams",
			comments: []string{
				"@matchExpression foo In bar baz",
			},
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rego := Rego{headerComments: tc.comments}
			matchers, err := rego.Matchers()
			if (err != nil && !tc.wantError) || (err == nil && tc.wantError) {
				t.Errorf("Unexpected error state, have %v want %v", !tc.wantError, tc.wantError)
			}
			actual := matchers.MatchExpressionsMatcher
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected MatchExpressionsMatcher, have %v want %v", actual, tc.expected)
			}
		})
	}
}

func TestGetStringListMatcher(t *testing.T) {
	testCases := []struct {
		desc      string
		tag       string
		comment   string
		expected  []string
		wantError bool
	}{
		{
			desc:      "InvalidTag",
			wantError: true, // will error without a match on the tag
		},
		{
			desc:      "NoValuesSupplied",
			tag:       "@foo",
			comment:   "@foo     ",
			wantError: true,
		},
		{
			desc:     "Valid",
			tag:      "@foo",
			comment:  "@foo bar baz",
			expected: []string{"bar", "baz"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			actual, err := getStringListMatcher(tc.tag, tc.comment)
			if (err != nil && !tc.wantError) || (err == nil && tc.wantError) {
				t.Errorf("Unexpected error state, have %v want %v", !tc.wantError, tc.wantError)
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected values, have %v want %v", actual, tc.expected)
			}
		})
	}
}
