# @title Containers must not run as privileged
#
# Privileged containers can easily escalate to root privileges on the node. As
# such containers running as privileged or with sufficient capabilities granted
# to obtain the same effect are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_privileged

import data.lib.core
import data.lib.pods
import data.lib.security

policyID := "P1003"

violation[msg] {
    pods.containers[container]
    container_is_privileged(container)

    msg = core.format_with_id(sprintf("%s/%s/%s: Containers must not run as privileged", [core.kind, core.name, container.name]), policyID)
}

container_is_privileged(container) {
    container.securityContext.privileged
}

container_is_privileged(container) {
    security.added_capability(container, "CAP_SYS_ADMIN")
}
