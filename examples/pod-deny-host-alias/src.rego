# @title Pods must not have access to the host aliases
#
# Pods that can change aliases in the host's /etc/hosts file can
# redirect traffic to malicious servers.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_host_alias

import data.lib.core
import data.lib.pods

policyID := "P1004"

violation[msg] {
    pod_host_alias

    msg := core.format(sprintf("%s/%s: Pod has hostAliases defined", [core.kind, core.name]), policyID)
}

pod_host_alias {
    pods.pod.spec.hostAliases
}
