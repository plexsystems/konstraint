{{/* This is an example how to create a CSV file that includes the policy ID and the policy name */}}
{{- range $severity, $value := . }}
{{- range . }}
{{ .Policy.PolicyID | default "-" }},{{ .Policy.Name }}
{{- end }}
{{- end }}
