# METADATA
# title: Pods must not run with access to the host networking
# description: |-
#   Pods that can access the host's network interfaces can potentially
#   access and tamper with traffic the pod should not have access to.
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
package pod_deny_host_network

import data.lib.core
import data.lib.pods

policyID := "P1006"

violation[msg] {
	pod_has_hostnetwork

	msg := core.format_with_id(sprintf("%s/%s: Pod allows for accessing the host network", [core.kind, core.name]), policyID)
}

pod_has_hostnetwork {
	pods.pod.spec.hostNetwork
}
