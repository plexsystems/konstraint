# METADATA
# title: Pods must not run with access to the host IPC
# description: |-
#   Pods that are allowed to access the host IPC can read memory of
#   the other containers, breaking that security boundary.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - ""
#       kinds:
#       - Pod
#     - apiGroups:
#       - apps
#       kinds:
#       - DaemonSet
#       - Deployment
#       - StatefulSet
package pod_deny_host_ipc

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P1005"

violation contains msg if {
	pod_has_hostipc

	msg := core.format_with_id(sprintf("%s/%s: Pod allows for accessing the host IPC", [core.kind, core.name]), policyID)
}

pod_has_hostipc if {
	pods.pod.spec.hostIPC
}
