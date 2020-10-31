package commands

const docTemplate = `# Policies
{{ range $severity, $value := . }}
## {{ $severity }}s

{{ range . }}* [{{ .Header.Title }}](#{{ .Header.Anchor }})
{{ end }}

{{- end }}

{{- range $severity, $value := . }}
{{- range $value }}
## {{ .Header.Title }}

**Severity:** {{ $severity }}

**Resources:** {{ .Header.Resources }}

{{- if .Header.Parameters }}

**Parameters:**

{{ range .Header.Parameters }}* {{ .Name }}: {{ if .IsArray }}array of {{ end }}{{ .Type }}
{{ end }}
{{- end }}

{{ .Header.Description }}

### Rego
{{ $codeblock := "` + "```" + `" }}
{{ $codeblock }}rego
{{ .Rego }}
{{ $codeblock }}

_source: [{{ .URL }}]({{ .URL }})_
{{ end }}

{{- end }}`
