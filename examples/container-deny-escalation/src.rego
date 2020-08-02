# @title Containers must not allow for privilege escalation
#
# Privileged containers can much more easily obtain root on the node.
# As such, they are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_escalation

import data.lib.core
import data.lib.pods

violation[msg] {
    container_allows_escalation

    msg := core.format(sprintf("%s/%s: Allows priviledge escalation", [core.kind, core.name]))
}


container_allows_escalation {
    pods.containers[_].securityContext.allowPrivilegeEscalation == true
}

container_allows_escalation {
    core.missing_field(pods.containers[_].securityContext, "allowPrivilegeEscalation")
}
