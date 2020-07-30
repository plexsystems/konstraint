package lib.workloads

import data.lib.core

pods[pod] {
  lower(core.kind) = "statefulset"
  pod = core.resource.spec.template
}

pods[pod] {
  lower(core.kind) = "daemonset"
  pod = core.resource.spec.template
}

pods[pod] {
  lower(core.kind) = "deployment"
  pod = core.resource.spec.template
}

pods[pod] {
  lower(core.kind) = "pod"
  pod = core.resource
}

pods[pod] {
  lower(core.kind) = "job"
  pod = core.resource.spec.template
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
  all_containers = pod_containers(core.resource)
  container = all_containers[_]
}

volumes[volume] {
  pods[pod]
  volume = pod.spec.volumes[_]
}
