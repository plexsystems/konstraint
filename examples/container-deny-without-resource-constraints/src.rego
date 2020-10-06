# @title Containers must define resource constraints
#
# Resource constraints on containers ensure that a given workload does not take up more resources than it requires
# and potentially starve other applications that need to run.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_without_resource_constraints

import data.lib.core
import data.lib.pods

policyID := "P2002"

violation[msg] {
    pods.containers[container]
    not container_resources_provided(container)

    msg := core.format_with_id(sprintf("%s/%s/%s: Container resource constraints must be specified", [core.kind, core.name, container.name]), policyID)
}

container_resources_provided(container) {
    container.resources.requests.cpu
    container.resources.requests.memory
    container.resources.limits.cpu
    container.resources.limits.memory
}
