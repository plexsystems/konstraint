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
	var rulesActionsTests = []struct {
		policy      string
		ruleCount   int
		ruleActions []string
	}{
		{"package test\ndefault test = true", 0, nil},
		{"package test\nviolation[msg] { msg = true }", 1, []string{"violation"}},
		{"package test\nwarn[msg] { msg = true }", 1, []string{"warn"}},
		{"package test\nviolation[msg] { msg = true }\nwarn[msg] { msg = true }", 2, []string{"violation", "warn"}},
		{"package test\nviolation[msg] { msg = true }\nviolation[msg] { msg = true }", 1, []string{"violation"}},
	}

	for _, test := range rulesActionsTests {
		regoFile, err := NewFile("test.rego", test.policy)
		if err != nil {
			t.Fatal("newRegoFile")
		}

		if len(regoFile.RuleNames) != test.ruleCount {
			t.Error("incorrect rule actions count")
		}

		if !reflect.DeepEqual(regoFile.RuleNames, test.ruleActions) {
			t.Errorf("incorrect rule actions\nreceived: %v\nexpected: %v", regoFile.RuleNames, test.ruleActions)
		}
	}
}

func TestGetPolicies(t *testing.T) {
	policies := getPolicies(testRegoFiles)
	if len(policies) != 2 {
		t.Error("incorrect number of policies loaded")
	}
}

func TestGetPoliciesWithAction(t *testing.T) {
	matchingPolicies := getFilesWithAction(testRegoFiles, "warn")
	if len(matchingPolicies) != 1 {
		t.Error("incorrect number of policies loaded")
	}
}
