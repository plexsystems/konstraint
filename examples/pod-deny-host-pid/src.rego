# @title Pods must not run with access to the host PID namespace
#
# Pods that can access the host's process tree can view and attempt to
# modify processes outside of their namespace, breaking that security
# boundary.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_host_pid

import data.lib.core
import data.lib.pods

violation[msg] {
    pod_has_hostpid

    msg := core.format(sprintf("%s/%s: Pod allows for accessing the host PID namespace", [core.kind, core.name]), policyID)
}

pod_has_hostpid {
    pods.pod.spec.hostPID
}
