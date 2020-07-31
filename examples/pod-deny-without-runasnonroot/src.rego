# @title Pods must run as non-root
# 
# Pods running as root (uid of 0) can much more easily escalate privileges
# to root on the node. As such, they are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_without_runasnonroot

import data.lib.pods
import data.lib.core

violation[msg] {
    pods.pods[pod]
    not pod.spec.securityContext.runAsNonRoot
    msg = core.format(sprintf("%s/%s/%s: Pod allows running as root", [core.kind, core.name, pod.metadata.name]))
}
