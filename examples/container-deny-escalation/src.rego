# @title Containers must not allow for privilege escalation
# 
# Privileged containers can much more easily obtain root on the node.
# As such, they are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_escalation

import data.lib.workloads
import data.lib.core

violation[msg] {
    workloads.containers[container]
    container.securityContext.allowPrivilegeEscalation
    msg = core.format(sprintf("%s/%s/%s: Allows priviledge escalation", [core.kind, core.name, container.name]))
}
