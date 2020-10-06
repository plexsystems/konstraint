# @title Pods must not run with access to the host networking
#
# Pods that can access the host's network interfaces can potentially
# access and tamper with traffic the pod should not have access to.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_host_network

import data.lib.core
import data.lib.pods

policyID := "P1006"

violation[msg] {
    pod_has_hostnetwork

    msg := core.format_with_id(sprintf("%s/%s: Pod allows for accessing the host network", [core.kind, core.name]), policyID)
}

pod_has_hostnetwork {
    pods.pod.spec.hostNetwork
}
