package commands

const docTemplate = `# Policies

{{ range $severity, $value := . }}## {{ $severity }}s

{{ range . }}* [{{ .Header.Title }}](#{{ .Header.Anchor }})
{{end}}
{{end}}

{{ range $severity, $value := . }}{{ range $value }}## {{ .Header.Title }}

**Severity:** {{ $severity }}

**Resources:** {{ .Header.Resources }}

{{ .Header.Description }}

### Rego` + "\n\n```rego\n" + "{{ .Rego }}\n" + "```\n" + `
_source: [{{ .URL }}]({{ .URL }})_

{{end}}
{{end}}
`
