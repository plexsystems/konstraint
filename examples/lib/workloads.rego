package lib.workloads

import data.lib.core

is_statefulset {
  lower(core.kind) == "statefulset"
}

is_daemonset {
  lower(core.kind) == "daemonset"
}

is_deployment {
  lower(core.kind) == "deployment"
}

is_pod {
  lower(core.kind) == "pod"
}

is_workload {
  containers[_]
}

pods[pod] {
  is_statefulset
  pod = core.resource.spec.template
}

pods[pod] {
  is_daemonset
  pod = core.resource.spec.template
}

pods[pod] {
  is_deployment
  pod = core.resource.spec.template
}

pods[pod] {
  is_pod
  pod = core.resource
}

volumes[volume] {
  pods[pod]
  volume = pod.spec.volumes[_]
}

pod_containers(pod) = all_containers {
  keys = {"containers", "initContainers"}
  all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
  pods[pod]
  all_containers = pod_containers(pod)
  container = all_containers[_]
}

containers[container] {
  all_containers = pod_containers(core.object)
  container = all_containers[_]
}
