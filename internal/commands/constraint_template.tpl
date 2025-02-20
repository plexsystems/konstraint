# This is a custom template for constraints
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
  {{- if ne .Enforcement "deny" }}
  enforcementAction: {{ .Enforcement }}
  {{- end -}}
  {{- if or .AnnotationKindMatchers .AnnotationNamespaceMatchers .AnnotationExcludedNamespaceMatchers .AnnotationLabelSelectorMatcher }}
  match:
  {{- if .AnnotationExcludedNamespaceMatchers }}
    excludedNamespaces: {{- .AnnotationExcludedNamespaceMatchers | toIndentYAML 2 | nindent 6 }}
  {{- end }}
  {{- if .AnnotationKindMatchers }}
    kinds: {{- .AnnotationKindMatchers | toJSON | fromJSON | toIndentYAML 2 | nindent 6 }}
  {{- end }}
  {{- if .AnnotationLabelSelectorMatcher }}
    labelSelector: {{- .AnnotationLabelSelectorMatcher | toJSON | fromJSON | toIndentYAML 2 | nindent 6 }}
  {{- end }}
  {{- if .AnnotationNamespaceMatchers }}
    namespaces: {{- .AnnotationNamespaceMatchers | toIndentYAML 2 | nindent 6 }}
  {{- end }}
  {{- end }}
