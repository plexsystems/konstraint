package lib.pods

import future.keywords.contains
import future.keywords.if

import data.lib.core

default pod := false

pod := core.resource.spec.template if {
	pod_templates := ["daemonset", "deployment", "job", "replicaset", "replicationcontroller", "statefulset"]
	lower(core.kind) == pod_templates[_]
}

pod := core.resource if {
	lower(core.kind) == "pod"
}

pod := core.resource.spec.jobTemplate.spec.template if {
	lower(core.kind) == "cronjob"
}

containers contains container if {
	keys := {"containers", "initContainers"}
	all_containers := [c | some k; keys[k]; c = pod.spec[k][_]]
	container := all_containers[_]
}

volumes contains pod.spec.volumes[_]
