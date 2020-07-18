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
