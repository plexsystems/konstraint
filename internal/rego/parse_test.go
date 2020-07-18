package rego

import (
	"reflect"
	"testing"
)

func TestGetModulesRulesActions(t *testing.T) {
	var rulesActionsTests = []struct {
		policy      string
		ruleCount   int
		ruleActions []string
	}{
		{"package test\ndefault test = true", 0, nil},
		{"package test\nviolation[msg] { msg = true }", 1, []string{"violation"}},
		{"package test\nwarn[msg] { msg = true }", 1, []string{"warn"}},
		{"package test\nviolation[msg] { msg = true }\nwarn[msg] { msg = true }", 2, []string{"violation", "warn"}},
	}

	for _, test := range rulesActionsTests {
		regoFile, err := newRegoFile("test.rego", test.policy)
		if err != nil {
			t.Fatal("newRegoFile")
		}

		if len(regoFile.RulesActions) != test.ruleCount {
			t.Error("incorrect rule count")
		}

		if !reflect.DeepEqual(regoFile.RulesActions, test.ruleActions) {
			t.Errorf("incorrect rule actions\nreceived: %v\nexpected: %v", regoFile.RulesActions, test.ruleActions)
		}
	}
}

func TestLoadPolicies(t *testing.T) {
	policyContents := make(map[string]string)
	policyContents["missingViolation.rego"] = `package test
default a = true`
	policyContents["withViolation.rego"] = `package test
violation[msg] {
	msg = "test"
}`

	policies, err := LoadPolicies(policyContents)
	if err != nil {
		t.Fatal("load policy files:", err)
	}

	if len(policies) != 1 {
		t.Error("incorrect number of policies loaded")
	}
}

func TestLoadPoliciesWithAction(t *testing.T) {
	policyContents := make(map[string]string)
	policyContents["missingViolation.rego"] = `package test
default a = true`
	policyContents["withViolation.rego"] = `package test
violation[msg] {
	msg = "test"
}`
	policyContents["withWarn.rego"] = `package test
warn[msg] {
	msg = "test"
}`

	policies, err := LoadPoliciesWithAction(policyContents, "warn")
	if err != nil {
		t.Fatal("load policy files:", err)
	}

	if len(policies) != 1 {
		t.Error("incorrect number of policies loaded")
	}
}

func TestLoadLibraries(t *testing.T) {
	libraryContents := make(map[string]string)
	libraryContents["missingViolation.rego"] = `package test
default a = true`
	libraryContents["withViolation.rego"] = `package test
violation[msg] {
	msg = "test"
}`

	policies, err := LoadLibraries(libraryContents)
	if err != nil {
		t.Fatal("load library files:", err)
	}

	if len(policies) != 2 {
		t.Error("incorrect number of libraries loaded")
	}
}
