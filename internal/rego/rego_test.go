package rego

import (
	"reflect"
	"testing"
)

var (
	testRegoFiles = []File{
		{
			FilePath:  "missingViolation.rego",
			Contents:  "package test\ndefault a = true",
			RuleNames: nil,
		},
		{
			FilePath:  "withViolation.rego",
			Contents:  "package test\nviolation[msg] { msg = true }",
			RuleNames: []string{"violation"},
		},
		{
			FilePath:  "withWarn.rego",
			Contents:  "package test\nwarn[msg] { msg = true }",
			RuleNames: []string{"warn"},
		},
	}
)

func TestNewFile_RuleNames(t *testing.T) {
	var rulesNamesTests = []struct {
		policy    string
		ruleCount int
		ruleNames []string
	}{
		{"package test\ndefault test = true", 1, []string{"test"}},
		{"package test\nviolation[msg] { msg = true }", 1, []string{"violation"}},
		{"package test\nwarn[msg] { msg = true }", 1, []string{"warn"}},
		{"package test\nviolation[msg] { msg = true }\nwarn[msg] { msg = true }", 2, []string{"violation", "warn"}},
		{"package test\nviolation[msg] { msg = true }\nviolation[msg] { msg = true }", 2, []string{"violation", "violation"}},
	}

	for _, test := range rulesNamesTests {
		regoFile, err := NewFile("test.rego", test.policy)
		if err != nil {
			t.Fatal("newRegoFile")
		}

		if len(regoFile.RuleNames) != test.ruleCount {
			t.Errorf("expected rule names count to be %v, but was %v", test.ruleCount, len(regoFile.RuleNames))
		}

		if !reflect.DeepEqual(regoFile.RuleNames, test.ruleNames) {
			t.Errorf("expected rule names to be %v, but was %v", test.ruleNames, regoFile.RuleNames)
		}
	}
}

func TestGetPoliciesWithRule(t *testing.T) {
	matchingPolicies := getFilesWithRule(testRegoFiles, "warn")
	if len(matchingPolicies) != 1 {
		t.Errorf("expected %v policies, but got %v", 1, len(matchingPolicies))
	}
}
