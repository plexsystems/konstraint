package policy

import data.lib.k8s

# @title Containers must define resource constraints
#
# Resource constraints on containers ensure that a given workload does not take up more resources than it required
# and potentially starve other applications that need to run.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
  containers_resource_constraints_required

  msg := k8s.format(sprintf("(%s) %s: Container resource constraints must be specified", [k8s.kind, k8s.name]))
}

containers_resource_constraints_required {
  k8s.is_workload
  not container_resources_provided
}

container_resources_provided {
  k8s.containers[_].resources.requests.cpu
  k8s.containers[_].resources.requests.memory
  k8s.containers[_].resources.limits.cpu
  k8s.containers[_].resources.limits.memory
}