package lib.containers

import data.lib.core
import data.lib.pods

pod_containers(pod) = all_containers {
  keys = {"containers", "initContainers"}
  all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
  pods.pods[pod]
  all_containers = pod_containers(pod)
  container = all_containers[_]
}

containers[container] {
  all_containers = pod_containers(core.resource)
  container = all_containers[_]
}

is_workload {
  containers[_]
}
