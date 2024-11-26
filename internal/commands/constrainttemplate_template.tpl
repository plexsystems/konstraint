apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: {{ .Name }}
spec:
  crd:
    spec:
      names:
        kind: {{ .Kind }}
      {{- if or .Parameters .AnnotationParameters }}
      validation:
        openAPIV3Schema:
          properties:
            {{- if .Parameters -}}
            {{ .GetOpenAPISchemaProperties | toJSON | fromJSON | toIndentYAML 2 | nindent 12 }}
            {{- else }}
            {{ .AnnotationParameters | toJSON | fromJSON | toIndentYAML 2 | nindent 12 }}
            {{- end }}
      {{- end }}
  targets:
  - libs: {{- range .Dependencies }}
    - |- {{- . | nindent 6 -}}
    {{ end }}
    rego: |- {{- .Source | nindent 6 }}
    target: admission.k8s.gatekeeper.sh
