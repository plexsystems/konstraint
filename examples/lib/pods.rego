package lib.pods

import data.lib.core

pods[pod] {
    lower(core.kind) == "statefulset"
    pod = core.resource.spec.template
}

pods[pod] {
    lower(core.kind) == "daemonset"
    pod = core.resource.spec.template
}

pods[pod] {
    lower(core.kind) == "deployment"
    pod = core.resource.spec.template
}

pods[pod] {
    lower(core.kind) == "pod"
    pod = core.resource
}

pods[pod] {
    lower(core.kind) == "job"
    pod = core.resource.spec.template
}

volumes[volume] {
    pods[pod]
    volume = pod.spec.volumes[_]
}
