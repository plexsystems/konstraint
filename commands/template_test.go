package commands

import (
	"testing"
)

func TestGetCRDYaml(t *testing.T) {
	expected := `
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
	name: name
spec:
	crd:
		spec:
			names:
				kind: kind
				listKind: listkindList
				plural: plural
				singular: singular
	targets:
		- target: admission.k8s.gatekeeper.sh
			rego: |
rego`

	data := ConstraintTemplate{
		Name:     "name",
		Kind:     "kind",
		ListKind: "listkindList",
		Plural:   "plural",
		Singular: "singular",
		Rego:     "rego",
	}

	actual, err := getCRDYaml(data)

	if err != nil {
		t.Fatalf("could not apply crd template")
	}

	if actual != expected {
		t.Errorf("crd was not generated as expected")
	}
}

func TestIndentTextByDefaultIndentsTextByEightSpaces(t *testing.T) {

	input := `this
is
some
text`

	expected := `        this
        is
        some
        text
`

	actual := indentText(input)

	if actual != expected {
		t.Errorf("text was not indented as expected")
	}
}
