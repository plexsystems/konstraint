# @title Containers must not allow for privilege escalation
# 
# Privileged containers can much more easily obtain root on the node.
# As such, they are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_escalation

import data.lib.core
import data.lib.containers

violation[msg] {
    containers.containers[container]
    allows_escalation(container)

    msg := core.format(sprintf("%s/%s/%s: Allows priviledge escalation", [core.kind, core.name, container.name]))
}

allows_escalation(c) {
    c.securityContext.allowPrivilegeEscalation == true
}

allows_escalation(c) {
    core.missing_field(c.securityContext, "allowPrivilegeEscalation")
}
