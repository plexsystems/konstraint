apiVersion: constraints.gatekeeper.sh/v1beta1
kind: {{ .Kind }}
metadata:
  {{- if .Annotations }}
  annotations: {{- .Annotations | toIndentYaml 2 | nindent 4 }}
  {{- end }}
  {{- if .Labels }}
  labels: {{ .Labels | toIndentYaml 2 | nindent 4 }}
  {{- end }}
  name: {{ .Name }}
spec:
  {{- if .Matchers }}
  match: {{ .GetAnnotation "matchers" | toIndentYaml 2 | nindent 4 }}
  {{- end }}
  {{- if ne .Enforcement "deny" }}
  enforcementAction: {{ .Enforcement }}
  {{- end -}}
  {{- if or .Parameters .AnnotationParameters }}
  {{- if .Parameters }}
  parameters: {{ .Parameters | toIndentYaml 2 | nindent 4 }}
  {{- end }}
  {{- end }}
