# @title Pods must run as non-root
#
# Pods running as root (uid of 0) can much more easily escalate privileges
# to root on the node. As such, they are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_without_runasnonroot

import data.lib.pods
import data.lib.core

policyID := "P1008"

violation[msg] {
    pods.pod
    not pod_runasnonroot

    msg := core.format_with_id(sprintf("%s/%s: Pod allows running as root", [core.kind, core.name]), policyID)
}

pod_runasnonroot {
    pods.pod.spec.securityContext.runAsNonRoot
}
