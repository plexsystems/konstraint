package commands

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus/hooks/test"

	"github.com/plexsystems/konstraint/internal/rego"
)

func TestRenderConstraint(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolations()
	if err != nil {
		t.Errorf("Error getting violations: %v", err)
	}

	expected, err := os.ReadFile("../../test/constraint_Test.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	expected = bytes.Replace(expected, []byte("\r"), []byte(""), -1)

	actual, err := renderConstraint(violations[0], "", entry.LastEntry())
	if err != nil {
		t.Errorf("Error rendering constraint: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.Replace(actual, []byte("\r"), []byte(""), -1)

	if !bytes.Equal(actual, expected) {
		t.Errorf("Unexpected rendered template:\n %v", cmp.Diff(string(expected), string(actual)))
	}
}

func TestRenderConstraintWithCustomTemplate(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolations()
	if err != nil {
		t.Errorf("Error getting violations: %v", err)
	}

	expected, err := os.ReadFile("../../test/custom/constraint_Test.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	expected = bytes.Replace(expected, []byte("\r"), []byte(""), -1)

	actual, err := renderConstraint(violations[0], "constraint_template.tpl", entry.LastEntry())
	if err != nil {
		t.Errorf("Error rendering constraint: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.Replace(actual, []byte("\r"), []byte(""), -1)

	if !bytes.Equal(actual, expected) {
		t.Errorf("Unexpected rendered template:\n %v", cmp.Diff(string(expected), string(actual)))
	}
}

func TestRenderConstraintTemplate(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolations()
	if err != nil {
		t.Errorf("Error getting violations: %v", err)
	}

	expected, err := os.ReadFile("../../test/template_Test.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on windows
	expected = bytes.Replace(expected, []byte("\r"), []byte(""), -1)

	actual, err := renderConstraintTemplate(violations[0], "v1beta1", "", entry.LastEntry())
	if err != nil {
		t.Errorf("Error rendering constrainttemplate: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.Replace(actual, []byte("\r"), []byte(""), -1)

	if !bytes.Equal(actual, expected) {
		t.Errorf("Unexpected rendered template:\n %v", cmp.Diff(string(expected), string(actual)))
	}
}

func TestRenderConstraintTemplateWithCustomTemplate(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolations()
	if err != nil {
		t.Errorf("Error getting violations: %v", err)
	}

	expected, err := os.ReadFile("../../test/custom/template_Test.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	expected = bytes.Replace(expected, []byte("\r"), []byte(""), -1)

	actual, err := renderConstraintTemplate(violations[0], "v1", "constrainttemplate_template.tpl", entry.LastEntry())

	if err != nil {
		t.Errorf("Error rendering constrainttemplate: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.Replace(actual, []byte("\r"), []byte(""), -1)

	if !bytes.Equal(actual, expected) {
		t.Errorf("Unexpected rendered template:\n %v", cmp.Diff(string(expected), string(actual)))
	}
}

func GetViolations() ([]rego.Rego, error) {
	violations, err := rego.GetViolations("../../test")
	if err != nil {
		return nil, err
	}
	return violations, nil
}
