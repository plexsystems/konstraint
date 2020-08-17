package commands

const docTemplate = `# Policies

## Violations

{{range .}}{{if .HasViolation}}* [{{.Header.Title}}](#{{.Header.Anchor}})
{{end}}{{end}}
## Warnings

{{range .}}{{if .HasWarning}}* [{{.Header.Title}}](#{{.Header.Anchor}})
{{end}}{{end}}

{{range .}}## {{.Header.Title}}

**Severity:** {{.Severities}}

**Resources:** {{.Header.Resources}}

{{.Header.Description}}

### Rego` + "\n\n```rego\n" + "{{.Rego}}\n" + "```\n" + `
_source: [{{.URL}}]({{.URL}})_

{{end}}`
