package commands

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/cobra"
)

// ConstraintTemplate represents the fields of the CRD that can be set
type ConstraintTemplate struct {
	Name     string
	Kind     string
	ListKind string
	Plural   string
	Singular string
	Rego     string
}

// NewTemplateCommand creates a new template command
func NewTemplateCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "template <rego file>",
		Short: "Create ConstraintTemplate CRD from a Rego policy",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return runTemplateCommand(args[0])
		},
	}

	return &cmd
}

func runTemplateCommand(path string) error {

	regoFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open path: %v", path)
	}

	regoContents, err := ioutil.ReadAll(regoFile)
	if err != nil {
		return fmt.Errorf("unable to read file: %v", regoFile)
	}

	regoAst := ast.MustParseModule(string(regoContents))
	if regoAst == nil {
		return fmt.Errorf("unable to parse rego file")
	}

	regoPackage := strings.Split(string(regoAst.Package.Location.Text), " ")[1]
	formattedRego := indentText(string(regoContents))
	data := ConstraintTemplate{
		Name:     regoPackage,
		Kind:     regoPackage,
		ListKind: regoPackage + "List",
		Plural:   regoPackage,
		Singular: regoPackage,
		Rego:     formattedRego,
	}

	crdText, err := getCRDYaml(data)
	if err != nil {
		return fmt.Errorf("unable to get yaml for CRD: %v", err)
	}

	writer, err := os.Create("template.yaml")
	if err != nil {
		return fmt.Errorf("unable to create yaml writer: %v", err)
	}

	_, err = writer.WriteString(crdText)
	if err != nil {
		return fmt.Errorf("unable to write CRD: %v", err)
	}

	return nil
}

func getCRDYaml(data ConstraintTemplate) (string, error) {
	crdTemplate := template.Must(template.New("constraintTemplate").Parse(`apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: {{.Name}}
spec:
  crd:
    spec:
      names:
        kind: {{.Kind}}
        listKind: {{.ListKind}}
        plural: {{.Plural}}
        singular: {{.Singular}}
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
{{.Rego}}`))

	buffer := bytes.NewBuffer(nil)
	err := crdTemplate.Execute(buffer, data)
	if err != nil {
		return "", fmt.Errorf("unable to create CRD template: %v", err)
	}

	return string(buffer.Bytes()), nil
}

func indentText(text string) string {
	var indentedText string
	const IndentationSize = 8

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if line != "" {
			line = strings.Repeat(" ", IndentationSize) + line
		}

		indentedText += line + "\n"
	}

	return indentedText
}
