# METADATA
# title: Containers must define resource constraints
# description: |-
#   Resource constraints on containers ensure that a given workload does not take up more resources than it requires
#   and potentially starve other applications that need to run.
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
package container_deny_without_resource_constraints

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P2002"

violation contains msg if {
	some container
	pods.containers[container]
	not container_resources_provided(container)

	msg := core.format_with_id(
		sprintf("%s/%s/%s: Container resource constraints must be specified", [core.kind, core.name, container.name]),
		policyID,
	)
}

container_resources_provided(container) if {
	container.resources.requests.cpu
	container.resources.requests.memory
	container.resources.limits.cpu
	container.resources.limits.memory
}
