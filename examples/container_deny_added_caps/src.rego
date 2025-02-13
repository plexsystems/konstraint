# METADATA
# title: Containers must drop all capabilities
# description: |-
#   Granting containers privileged capabilities on the node makes it easier
#   for containers to escalate their privileges. As such, this is not allowed
#   outside of Kubernetes controller namespaces.
# custom:
#   annotations:
#     "argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true"
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
package container_deny_added_caps

import data.lib.core
import data.lib.pods
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P1001"

violation contains msg if {
	some container
	pods.containers[container]
	not container_dropped_all_capabilities(container)

	msg := core.format_with_id(
		sprintf("%s/%s/%s: Does not drop all capabilities", [core.kind, core.name, container.name]),
		policyID,
	)
}

container_dropped_all_capabilities(container) if {
	security.dropped_capability(container, "all")
}
