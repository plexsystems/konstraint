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

policyID := "P1005"

violation[msg] {
	pod_has_hostipc

	msg := core.format_with_id(sprintf("%s/%s: Pod allows for accessing the host IPC", [core.kind, core.name]), policyID)
}

pod_has_hostipc {
	pods.pod.spec.hostIPC
}
