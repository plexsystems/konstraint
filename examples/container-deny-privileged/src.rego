# @title Containers must not run as privileged
# 
# Privileged containers can much more easily obtain root on the node.
# As such, they are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_privileged

import data.lib.core
import data.lib.workloads
import data.lib.security

violation[msg] {
    workloads.containers[container]
    is_privileged(container)

    msg = core.format(sprintf("%s/%s/%s: Is privileged", [core.kind, core.name, container.name]))
}

is_privileged(container) {
  container.securityContext.privileged
}

is_privileged(container) {
  security.added_capability(container, "CAP_SYS_ADMIN")
}
