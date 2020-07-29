package container_resource_constraints

import data.lib.core
import data.lib.workloads

# @title Containers must define resource constraints
#
# Resource constraints on containers ensure that a given workload does not take up more resources than it required
# and potentially starve other applications that need to run.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
  workloads.containers[container]
  not container_resources_provided(container)

  msg := core.format(sprintf("(%s) %s: Container resource constraints must be specified", [core.kind, core.name]))
}

container_resources_provided(container) {
  container.resources.requests.cpu
  container.resources.requests.memory
  container.resources.limits.cpu
  container.resources.limits.memory
}
