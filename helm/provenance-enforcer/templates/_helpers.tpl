{{- define "provenance-enforcer.name" -}}
provenance-enforcer
{{- end -}}

{{- define "provenance-enforcer.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "provenance-enforcer.hmacSecretName" -}}
{{- default "provenance-enforcer-hmac" .Values.hmacSecret.name -}}
{{- end -}}

{{- define "provenance-enforcer.hmacSecretKeyField" -}}
{{- default "key" .Values.hmacSecret.keyField -}}
{{- end -}}