# Policies
{{ range $severity, $value := . }}
## {{ $severity }}{{- if ne $severity "Not Enforced" }}s{{ end }}

{{ range . }}* [{{ .Header.Title }}](#{{ .Header.Anchor }})
{{ end }}

{{- end }}

{{- range $severity, $value := . }}
{{- range $value }}
## {{ .Header.Title }}

**Severity:** {{ $severity }}

**Resources:** {{ .Header.Resources }}

{{- if .Header.MatchLabels }}

**MatchLabels:** {{ .Header.MatchLabels }}
{{- end }}

{{- if .Header.Parameters }}

**Parameters:**
{{ range .Header.Parameters }}
* {{ .Name }}: {{ if .IsArray }}array of {{ end }}{{ .Type }}
{{- if .Description }}
  {{ .Description }}{{- end -}}
{{ end }}
{{- end }}

{{ .Header.Description }}
{{ if ne .Rego "" }}
### Rego
{{ $codeblock := "```" }}
{{ $codeblock }}rego
{{ .Rego }}
{{ $codeblock }}{{- end }}

_source: [{{ .URL }}]({{ .URL }})_
{{ end }}

{{- end }}
