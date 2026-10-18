{{- define "daviante-doh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "daviante-doh.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "daviante-doh.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "daviante-doh.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "daviante-doh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "daviante-doh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "daviante-doh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "daviante-doh.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "daviante-doh.containerPort" -}}
{{- last (splitList ":" .Values.config.listenAddress) -}}
{{- end -}}

{{- define "daviante-doh.adminPort" -}}
{{- if .Values.config.adminListenAddress -}}
{{- last (splitList ":" .Values.config.adminListenAddress) -}}
{{- end -}}
{{- end -}}
