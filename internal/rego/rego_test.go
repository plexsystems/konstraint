package rego

import (
	"testing"

	"github.com/open-policy-agent/opa/ast"
)

func TestKind(t *testing.T) {
	policy, err := Parse("../../test/src.rego")
	if err != nil {
		t.Fatal("unable to parse policy")
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
	policy := newPolicy()

	actual := policy.Title()

	const expected = "The title"
	if actual != expected {
		t.Errorf("unexpected Title. expected %v, actual %v", expected, actual)
	}
}

func TestDescription(t *testing.T) {
	policy := newPolicy()

	actual := policy.Description()

	const expected = "The description"
	if actual != expected {
		t.Errorf("unexpected Description. expected %v, actual %v", expected, actual)
	}
}

func TestSeverity(t *testing.T) {
	policy := newPolicy()

	actual := policy.Severity()

	const expected = "Violation"
	if actual != expected {
		t.Errorf("unexpected Severity. expected %v, actual %v", expected, actual)
	}
}

func TestSource(t *testing.T) {
	policy := newPolicy()

	actual := policy.Source()

	const expected = `package test

import data.lib.core
import data.lib.pods

violation[msg] {
	true
}`

	if actual != expected {
		t.Errorf("unexpected Source. expected %v, actual %v", expected, actual)
	}
}

func newPolicy() Rego {
	policy := `
# @title The title
#
# The description
#
# @kinds apps/Deployment core/Pod 
package test

import data.lib.core
import data.lib.pods

# The comment
violation[msg] {
	true
}`

	module, _ := ast.ParseModule("", policy)
	rego := Rego{
		contents: policy,
		module:   module,
	}

	return rego
}
