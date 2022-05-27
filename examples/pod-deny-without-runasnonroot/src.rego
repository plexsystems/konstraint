# METADATA
# title: Pods must run as non-root
# description: |-
#   Pods running as root (uid of 0) can much more easily escalate privileges
#   to root on the node. As such, they are not allowed.
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
package pod_deny_without_runasnonroot

import data.lib.core
import data.lib.pods

policyID := "P1008"

violation[msg] {
	pods.pod
	not pod_runasnonroot

	msg := core.format_with_id(sprintf("%s/%s: Pod allows running as root", [core.kind, core.name]), policyID)
}

pod_runasnonroot {
	pods.pod.spec.securityContext.runAsNonRoot
}
