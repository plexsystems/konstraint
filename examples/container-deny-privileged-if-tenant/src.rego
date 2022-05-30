# METADATA
# title: Tenants' containers must not run as privileged
# description: |-
#   Privileged containers can easily escalate to root privileges on the node. As
#   such containers running as privileged or with sufficient capabilities granted
#   to obtain the same effect are not allowed if they are labeled as tenant.
#   To take advantage of this policy, it must be combined with another policy
#   that enforces the 'is-tenant' label.
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
#     labelSelector:
#       matchLabels:
#         is-tenant: "true"
package container_deny_privileged_if_tenant

import data.lib.core
import data.lib.pods
import data.lib.security

policyID := "P2006"

violation[msg] {
	pods.containers[container]
	container_is_privileged(container)

	msg = core.format_with_id(sprintf("%s/%s/%s: Tenants' containers must not run as privileged", [core.kind, core.name, container.name]), policyID)
}

container_is_privileged(container) {
	container.securityContext.privileged
}

container_is_privileged(container) {
	security.added_capability(container, "CAP_SYS_ADMIN")
}
