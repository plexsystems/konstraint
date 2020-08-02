# @title Containers must drop all capabilitites
#
# Granting containers privileged capabilities on the node makes it easier
# for containers to escalate their privileges. As such, this is not allowed
# outside of Kubernetes controller namespaces.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_added_caps

import data.lib.core
import data.lib.pods
import data.lib.security

violation[msg] {
    pods.containers[container]
    not security.dropped_capability(container, "all")

    msg := core.format(sprintf("%s/%s/%s: Does not drop all capabilities", [core.kind, core.name, container.name]))
}
