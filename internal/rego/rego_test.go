package rego

import (
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/ast"
)

func TestKind(t *testing.T) {
	policy := Rego{
		path: "some/path/my-policy/src.rego",
	}

	actual := policy.Kind()

	const expected = "MyPolicy"
	if actual != expected {
		t.Errorf("unexpected Kind. expected %v, actual %v", expected, actual)
	}
}

func TestName(t *testing.T) {
	policy := Rego{
		path: "some/path/my-policy/src.rego",
	}

	actual := policy.Name()

	const expected = "mypolicy"
	if actual != expected {
		t.Errorf("unexpected Name. expected %v, actual %v", expected, actual)
	}
}

func TestTitle(t *testing.T) {
	comments := `
# METADATA
# title: The Title
# description: |- 
#  The description
#  Extra comment
package foo
foo = "bar" { true }
`
	rule, err := ast.ParseModuleWithOpts("", comments, ast.ParserOptions{ProcessAnnotation: true})

	if err != nil {
		t.Errorf("Error parsing module: %s", err)
	}
	rego := Rego{}

	err = rego.parseAnnotations(rule.Annotations[0])

	if err != nil {
		t.Errorf("Error parsing annotations: %s", err)
	}
	actual := rego.Title()

	const expected = "The Title"
	if actual != expected {
		t.Errorf("unexpected Title. expected %v, actual %v", expected, actual)
	}
}

func TestDescription(t *testing.T) {
	comments := `
# METADATA
# title: The Title
# description: |- 
#  The description
#  Extra comment
package foo
foo = "bar" { true }
		`

	rule, err := ast.ParseModuleWithOpts("", comments, ast.ParserOptions{ProcessAnnotation: true})

	if err != nil {
		t.Errorf("Error parsing module: %s", err)
	}

	rego := Rego{}

	err = rego.parseAnnotations(rule.Annotations[0])

	if err != nil {
		t.Errorf("Error parsing annotations: %s", err)
	}

	actual := rego.Description()

	const expected = "The description\nExtra comment"
	if actual != expected {
		t.Errorf("unexpected Description. expected %v, actual %v", expected, actual)
	}
}

func TestSeverity(t *testing.T) {
	rules := []string{
		"violation",
		"warn",
	}

	rego := Rego{
		rules: rules,
	}

	actual := rego.Severity()

	const expected = Violation
	if actual != expected {
		t.Errorf("unexpected Severity. expected %v, actual %v", expected, actual)
	}
}

func TestSource(t *testing.T) {
	raw := `first
# second
third
# fourth
`

	rego := Rego{
		sanitizedRaw: raw,
	}

	actual := rego.Source()

	const expected = `first
third`

	if actual != expected {
		t.Errorf("unexpected Source. expected %v, actual %v", expected, actual)
	}
}

func TestEnforcement(t *testing.T) {
	actualDefault := Rego{}.Enforcement()
	const expectedDefault = "deny"
	if actualDefault != expectedDefault {
		t.Errorf("unexpected Enforcement. expected %v, actual %v", expectedDefault, actualDefault)
	}
}

func TestGetPolicyID(t *testing.T) {
	rules := []*ast.Rule{
		{
			Head: &ast.Head{
				Name: "policyID",
				Value: &ast.Term{
					Value: ast.MustInterfaceToValue("P123456"),
				},
			},
		},
	}

	const expected = "P123456"
	actual := getPolicyID(rules)
	if actual != expected {
		t.Errorf("unexpected policyID. expected %v, actual %v", expected, actual)
	}
}

func TestGetPolicyID_Null(t *testing.T) {
	rules := []*ast.Rule{}

	const expected = ""
	actual := getPolicyID(rules)
	if actual != expected {
		t.Errorf("unexpected policyID. expected %v, actual %v", expected, actual)
	}
}

func TestGetRuleParamNamesFromInput(t *testing.T) {
	testCases := []struct {
		desc string
		rule string
		want []string
	}{
		{
			desc: "No Parameters",
			rule: `foo = "bar" { true }`,
		},
		{
			desc: "Parameters in rule body",
			rule: `violation[msg] {
				foo := "bar"
				bar := input.parameters.baz
				baz := input.parameters.foobars[_]
				box := input.parameters.baz
			}`,
			want: []string{"baz", "foobars"},
		},
		{
			desc: "Parameters in rule value",
			rule: `foo = input.parameters.bar { true }`,
			want: []string{"bar"},
		},
		{
			desc: "Parameters in body and value",
			rule: `foo = input.parameters.bar {
				x := input.parameters.baz
			}`,
			want: []string{"bar", "baz"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			rule, err := ast.ParseRule(tc.rule)
			if err != nil {
				t.Fatalf("parse rule: %s", err)
			}

			actual := getRuleParamNames([]*ast.Rule{rule})
			if !(reflect.DeepEqual(tc.want, actual)) {
				t.Errorf("unexpected bodyParams. expected %+v, actual %+v", tc.want, actual)
			}
		})
	}
}
