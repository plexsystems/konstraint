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

	expected, err := os.ReadFile("../../test/output/standard/constraint_FullMetadata.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	expected = bytes.ReplaceAll(expected, []byte("\r"), []byte(""))

	actual, err := renderConstraint(violations[0], "", entry.LastEntry())
	if err != nil {
		t.Errorf("Error rendering constraint: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.ReplaceAll(actual, []byte("\r"), []byte(""))

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

	expected, err := os.ReadFile("../../test/output/custom/constraint_FullMetadata.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	expected = bytes.ReplaceAll(expected, []byte("\r"), []byte(""))

	actual, err := renderConstraint(violations[0], "constraint_template.tpl", entry.LastEntry())
	if err != nil {
		t.Errorf("Error rendering constraint: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.ReplaceAll(actual, []byte("\r"), []byte(""))

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

	expected, err := os.ReadFile("../../test/output/standard/template_FullMetadata.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on windows
	expected = bytes.ReplaceAll(expected, []byte("\r"), []byte(""))

	actual, err := renderConstraintTemplate(violations[0], "v1", "", entry.LastEntry())
	if err != nil {
		t.Errorf("Error rendering constrainttemplate: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.ReplaceAll(actual, []byte("\r"), []byte(""))

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

	expected, err := os.ReadFile("../../test/output/custom/template_FullMetadata.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	expected = bytes.ReplaceAll(expected, []byte("\r"), []byte(""))

	actual, err := renderConstraintTemplate(violations[0], "v1", "constrainttemplate_template.tpl", entry.LastEntry())

	if err != nil {
		t.Errorf("Error rendering constrainttemplate: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.ReplaceAll(actual, []byte("\r"), []byte(""))

	if !bytes.Equal(actual, expected) {
		t.Errorf("Unexpected rendered template:\n %v", cmp.Diff(string(expected), string(actual)))
	}
}

func GetViolations() ([]rego.Rego, error) {
	violations, err := rego.GetViolations("../../test/policies/")
	if err != nil {
		return nil, err
	}
	return violations, nil
}
