package lib.workloads

import data.lib.core

pods[pod] {
  core.kind = "StatefulSet"
  pod = core.resource.spec.template
}

pods[pod] {
  core.kind = "DaemonSet"
  pod = core.resource.spec.template
}

pods[pod] {
  core.kind = "Deployment"
  pod = core.resource.spec.template
}

pods[pod] {
  core.kind = "Pod"
  pod = core.resource
}

pods[pod] {
  core.kind = "Job"
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
