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
  pod = core.object.spec.template
}

pods[pod] {
  is_daemonset
  pod = core.object.spec.template
}

pods[pod] {
  is_deployment
  pod = core.object.spec.template
}

pods[pod] {
  is_pod
  pod = core.object
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

container_images[image] {
  containers[container]
  image = container.image
}

split_image(image) = [image, "latest"] {
  not contains(image, ":")
}

split_image(image) = [image_name, tag] {
  [image_name, tag] = split(image, ":")
}
