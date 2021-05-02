package commands

const docTemplate = `# Policies
{{ range $severity, $value := .Documentation }}
## {{ $severity }}{{- if ne $severity "Not Enforced" }}s{{ end }}

{{ range . }}* [{{ .Header.Title }}](#{{ .Header.Anchor }})
{{ end }}

{{- end }}

{{- range $severity, $value := .Documentation }}
{{- range $value }}
## {{ .Header.Title }}

**Severity:** {{ $severity }}

**Resources:** {{ .Header.Resources }}

{{- if .Header.MatchLabels }}

**MatchLabels:** {{ .Header.MatchLabels }}
{{- end }}

{{- if .Header.Parameters }}

**Parameters:**

{{ range .Header.Parameters }}* {{ .Name }}: {{ if .IsArray }}array of {{ end }}{{ .Type }}
{{ end }}
{{- end }}

{{ .Header.Description }}
{{ if $.IncludeRego }}
### Rego
{{ $codeblock := "` + "```" + `" }}
{{ $codeblock }}rego
{{ .Rego }}
{{ $codeblock }}{{- end }}

_source: [{{ .URL }}]({{ .URL }})_
{{ end }}

{{- end }}`
