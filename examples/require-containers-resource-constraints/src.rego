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
  containers_resource_constraints_required

  msg := core.format(sprintf("(%s) %s: Container resource constraints must be specified", [core.kind, core.name]))
}

containers_resource_constraints_required {
  workloads.is_workload
  not container_resources_provided
}

container_resources_provided {
  workloads.containers[_].resources.requests.cpu
  workloads.containers[_].resources.requests.memory
  workloads.containers[_].resources.limits.cpu
  workloads.containers[_].resources.limits.memory
}
