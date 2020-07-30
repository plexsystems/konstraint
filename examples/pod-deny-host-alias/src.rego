# @title Pods must not have access to the host aliases
# 
# Pods that can change aliases in the host's /etc/hosts file can 
# redirect traffic to malicious servers.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package pod_deny_host_alias

import data.lib.core
import data.lib.workloads

violation[msg] {
    workloads.pods[pod]
    pod.spec.hostAliases
    msg = core.format(sprintf("%s/%s/%s: Pod allows for managing host aliases", [core.kind, core.name, pod.metadata.name]))
}
