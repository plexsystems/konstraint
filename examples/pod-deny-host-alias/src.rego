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

import data.lib.core.format_with_id
import data.lib.core.kind
import data.lib.core.name
import data.lib.pods

policyID := "P1004"

violation[msg] {
	pod_host_alias

	msg := format_with_id(sprintf("%s/%s: Pod has hostAliases defined", [kind, name]), policyID)
}

pod_host_alias {
	pods.pod.spec.hostAliases
}
