# METADATA
# title: Containers must not allow for privilege escalation
# description: |-
#   Privileged containers can much more easily obtain root on the node.
#   As such, they are not allowed.
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
package container_deny_escalation

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P1002"

violation contains msg if {
	some container
	pods.containers[container]
	container_allows_escalation(container)

	msg := core.format_with_id(sprintf("%s/%s: Allows privilege escalation", [core.kind, core.name]), policyID)
}

container_allows_escalation(c) if {
	c.securityContext.allowPrivilegeEscalation == true
}

container_allows_escalation(c) if {
	core.missing_field(c, "securityContext")
}

container_allows_escalation(c) if {
	core.missing_field(c.securityContext, "allowPrivilegeEscalation")
}
