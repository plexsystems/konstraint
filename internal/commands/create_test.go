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

	actual, err := renderConstraintTemplate(violations[0], "v1", "", false, entry.LastEntry())
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

	actual, err := renderConstraintTemplate(violations[0], "v1", "constrainttemplate_template.tpl", false, entry.LastEntry())

	if err != nil {
		t.Errorf("Error rendering constrainttemplate: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	actual = bytes.ReplaceAll(actual, []byte("\r"), []byte(""))

	if !bytes.Equal(actual, expected) {
		t.Errorf("Unexpected rendered template:\n %v", cmp.Diff(string(expected), string(actual)))
	}
}

func TestRenderConstraintTemplateWithCustomTemplateV1(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolationsV1()
	if err != nil {
		t.Errorf("Error getting violations: %v", err)
	}

	expected, err := os.ReadFile("../../test/output/custom/template_FullMetadata_v1.yaml")
	if err != nil {
		t.Errorf("Error reading expected file: %v", err)
	}

	// Need to remove carriage return for testing on Windows
	expected = bytes.ReplaceAll(expected, []byte("\r"), []byte(""))

	actual, err := renderConstraintTemplate(violations[0], "v1", "constrainttemplate_template.tpl", true, entry.LastEntry())

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
	violations, err := rego.GetViolations("../../test/policies/", rego.V0)
	if err != nil {
		return nil, err
	}
	return violations, nil
}

func GetViolationsV1() ([]rego.Rego, error) {
	violations, err := rego.GetViolations("../../test/policies/", rego.V1)
	if err != nil {
		return nil, err
	}
	return violations, nil
}

func TestRenderConstraintTemplateV0Format(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolations()
	if err != nil {
		t.Fatalf("Error getting violations: %v", err)
	}

	if len(violations) == 0 {
		t.Fatal("No violations found")
	}

	actual, err := renderConstraintTemplate(violations[0], "v1", "", false, entry.LastEntry())
	if err != nil {
		t.Fatalf("Error rendering constrainttemplate: %v", err)
	}

	if bytes.Contains(actual, []byte("code:")) {
		t.Error("v0 template should not contain 'code:' field")
	}
	if bytes.Contains(actual, []byte("engine: Rego")) {
		t.Error("v0 template should not contain 'engine: Rego'")
	}
	if !bytes.Contains(actual, []byte("libs:")) {
		t.Error("v0 template should contain 'libs:' field")
	}
	if !bytes.Contains(actual, []byte("rego: |")) {
		t.Error("v0 template should contain 'rego: |' field")
	}
}

func TestRenderConstraintTemplateV1Format(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolationsV1()
	if err != nil {
		t.Fatalf("Error getting v1 violations: %v", err)
	}

	if len(violations) == 0 {
		t.Fatal("No violations found")
	}

	actual, err := renderConstraintTemplate(violations[0], "v1", "", true, entry.LastEntry())
	if err != nil {
		t.Fatalf("Error rendering constrainttemplate: %v", err)
	}

	if !bytes.Contains(actual, []byte("code:")) {
		t.Error("v1 template should contain 'code:' field")
	}
	if !bytes.Contains(actual, []byte("engine: Rego")) {
		t.Error("v1 template should contain 'engine: Rego'")
	}
	if !bytes.Contains(actual, []byte("source:")) {
		t.Error("v1 template should contain 'source:' field")
	}
	if !bytes.Contains(actual, []byte("version: v1")) {
		t.Error("v1 template should contain 'version: v1' in source")
	}
	if bytes.Contains(actual, []byte("import future.keywords")) {
		t.Error("v1 template with strip-v0-imports should not contain 'import future.keywords'")
	}
}

func TestRenderConstraintTemplateV1StripImports(t *testing.T) {
	_, entry := log.NewNullLogger()

	violations, err := GetViolationsV1()
	if err != nil {
		t.Fatalf("Error getting v1 violations: %v", err)
	}

	if len(violations) == 0 {
		t.Fatal("No violations found")
	}

	withImports, err := renderConstraintTemplate(violations[0], "v1", "", false, entry.LastEntry())
	if err != nil {
		t.Fatalf("Error rendering constrainttemplate: %v", err)
	}

	withoutImports, err := renderConstraintTemplate(violations[0], "v1", "", true, entry.LastEntry())
	if err != nil {
		t.Fatalf("Error rendering constrainttemplate: %v", err)
	}

	for _, actual := range [][]byte{withImports, withoutImports} {
		if !bytes.Contains(actual, []byte("code:")) {
			t.Error("v1 template should contain 'code:' field")
		}
		if !bytes.Contains(actual, []byte("engine: Rego")) {
			t.Error("v1 template should contain 'engine: Rego'")
		}
		if !bytes.Contains(actual, []byte("version: v1")) {
			t.Error("v1 template should contain 'version: v1' in source")
		}
	}

	if bytes.Contains(withoutImports, []byte("import future.keywords")) {
		t.Error("v1 template with strip-v0-imports=true should not contain 'import future.keywords'")
	}
	if bytes.Contains(withoutImports, []byte("import rego.v1")) {
		t.Error("v1 template with strip-v0-imports=true should not contain 'import rego.v1'")
	}
}
