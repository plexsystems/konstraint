package deny_privileged_containers

import data.lib.core
import data.lib.workloads
import data.lib.security

# @title Containers must not run as privileged
#
# Privileged containers can easily escalate to root privileges on the node. As
# such containers running as privileged or with sufficient capabilities granted
# to obtain the same effect are not allowed.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod

violation[msg] {
  workloads.containers[container]
  is_privileged(container)

  msg = core.format(sprintf("%s/%s/%s: Containers are not allowed to run as privileged", [core.kind, core.name, container.name]))
}

is_privileged(container) {
  container.securityContext.privileged
}

is_privileged(container) {
  security.added_capability(container, "CAP_SYS_ADMIN")
}
