# @title Pods must not run with access to the host IPC
#
# Pods that are allowed to access the host IPC can read memory of
# the other containers, breaking that security boundary.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_host_ipc

import data.lib.core
import data.lib.pods

policyID := "P1005"

violation[msg] {
    pod_has_hostipc

    msg := core.format(sprintf("%s/%s: Pod allows for accessing the host IPC", [core.kind, core.name]), policyID)
}

pod_has_hostipc {
    pods.pod.spec.hostIPC
}
