package rego

import (
	"fmt"
	"strings"
	"testing"
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
	policy, err := newPolicy()
	if err != nil {
		t.Fatal("new policy:", err)
	}

	actual := policy.Title()

	const expected = "The title"
	if actual != expected {
		t.Errorf("unexpected Title. expected %v, actual %v", expected, actual)
	}
}

func TestDescription(t *testing.T) {
	policy, err := newPolicy()
	if err != nil {
		t.Fatal("new policy:", err)
	}

	actual := policy.Description()

	const expected = "The description"
	if actual != expected {
		t.Errorf("unexpected Description. expected %v, actual %v", expected, actual)
	}
}

func TestSeverity(t *testing.T) {
	policy, err := newPolicy()
	if err != nil {
		t.Fatal("new policy:", err)
	}

	actual := policy.Severity()

	const expected = "Violation"
	if actual != expected {
		t.Errorf("unexpected Severity. expected %v, actual %v", expected, actual)
	}
}

func TestSource(t *testing.T) {
	policy, err := newPolicy()
	if err != nil {
		t.Fatal("new policy:", err)
	}

	actual := policy.Source()

	const expected = `package test

import data.lib.libraryA

violation[msg] {
    true
}
`

	if !strings.EqualFold(actual, expected) {
		t.Errorf("unexpected Source. expected %v, actual %v", expected, actual)
	}
}

func newPolicy() (Rego, error) {
	rego, err := Parse("../../test/src.rego")
	if err != nil {
		return Rego{}, fmt.Errorf("parse: %w", err)
	}

	return rego, nil
}
