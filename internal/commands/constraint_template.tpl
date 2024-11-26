apiVersion: constraints.gatekeeper.sh/v1beta1
kind: {{ .Kind }}
metadata:
  {{- if .Annotations }}
  annotations: {{- .Annotations | toIndentYAML 2 | nindent 4 }}
  {{- end }}
  {{- if .Labels }}
  labels: {{ .Labels | toIndentYAML 2 | nindent 4 }}
  {{- end }}
  name: {{ .Name }}
spec:
  {{- if .Matchers }}
  match: {{- .GetAnnotation "matchers" | toIndentYAML 2 | nindent 4 }}
  {{- end }}
  {{- if ne .Enforcement "deny" }}
  enforcementAction: {{ .Enforcement }}
  {{- end -}}
  {{- if .AnnotationParameters }}
  parameters: {{- .AnnotationParameters | toIndentYAML 2 | nindent 4 }}
  {{- end }}
