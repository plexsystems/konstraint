# METADATA
# title: Pods must not have access to the host aliases
# description: >-
#   Pods that can change aliases in the host's /etc/hosts file can
#   redirect traffic to malicious servers.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - ""
#       kinds:
#       - Pod
#     - apiGroups:
#       - apps
#       kinds:
#       - DaemonSet
#       - Deployment
#       - StatefulSet
package pod_deny_host_alias

import future.keywords.contains
import future.keywords.if

import data.lib.core.format_with_id
import data.lib.core.kind
import data.lib.core.name
import data.lib.pods

policyID := "P1004"

violation contains msg if {
	pod_host_alias

	msg := format_with_id(sprintf("%s/%s: Pod has hostAliases defined", [kind, name]), policyID)
}

pod_host_alias if {
	pods.pod.spec.hostAliases
}
