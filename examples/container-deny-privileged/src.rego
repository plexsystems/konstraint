package container_deny_privileged

import data.lib.core
import data.lib.pods
import data.lib.security

# @title Containers must not run as privileged
#
# Privileged containers can easily escalate to root privileges on the node. As
# such containers running as privileged or with sufficient capabilities granted
# to obtain the same effect are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod

violation[msg] {
  pods.containers[container]
  is_privileged(container)

  msg = core.format(sprintf("%s/%s/%s: Containers must not run as privileged", [core.kind, core.name, container.name]))
}

is_privileged(container) {
  container.securityContext.privileged
}

is_privileged(container) {
  security.added_capability(container, "CAP_SYS_ADMIN")
}
