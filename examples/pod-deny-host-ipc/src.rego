# @title Pods must not run with access to the host IPC
# 
# Pods that are allowed to access the host IPC can read memory of
# the other containers, breaking that security boundary.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_host_ipc

import data.lib.core
import data.lib.workloads

violation[msg] {
    workloads.pods[pod]
    pod.spec.hostIPC
    msg = core.format(sprintf("%s/%s/%s: Pod allows for accessing the host IPC", [core.kind, core.name, pod.metadata.name]))
}
