# METADATA
# title: Containers must not run as privileged
# description: |-
#   Privileged containers can easily escalate to root privileges on the node. As
#   such containers running as privileged or with sufficient capabilities granted
#   to obtain the same effect are not allowed.
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
package container_deny_privileged

import data.lib.core
import data.lib.pods
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P1003"

violation contains msg if {
	some container
	pods.containers[container]
	container_is_privileged(container)

	msg := core.format_with_id(
		sprintf("%s/%s/%s: Containers must not run as privileged", [core.kind, core.name, container.name]),
		policyID,
	)
}

container_is_privileged(container) if {
	container.securityContext.privileged
}

container_is_privileged(container) if {
	security.added_capability(container, "CAP_SYS_ADMIN")
}
