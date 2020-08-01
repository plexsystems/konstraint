package lib.pods

import data.lib.core

pod = core.resource.spec.template {
    pod_templates := ["daemonset","deployment","job","statefulset"]
    lower(core.kind) == pod_templates[_]
}

pod = core.resource {
    lower(core.kind) == "pod"
}

containers[container] {
    keys = {"containers", "initContainers"}
    all_containers = [c | keys[k]; c = pod.spec[k][_]]
    container = all_containers[_]
}

volumes[volume] {
    volume = pod.spec.volumes[_]
}
