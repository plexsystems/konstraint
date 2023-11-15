# METADATA
# title: Pods must not run with access to the host PID namespace
# description: |-
#   Pods that can access the host's process tree can view and attempt to
#   modify processes outside of their namespace, breaking that security
#   boundary.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - ""
#       kinds:
#       - Pod
#     - apiGroups:
#       - apps
#       kinds:
#       - DaemonSet
#       - Deployment
#       - StatefulSet
package pod_deny_host_pid

import data.lib.core
import data.lib.pods

policyID := "P1007"

violation[msg] {
	pod_has_hostpid

	msg := core.format_with_id(
		sprintf("%s/%s: Pod allows for accessing the host PID namespace", [core.kind, core.name]),
		policyID,
	)
}

pod_has_hostpid {
	pods.pod.spec.hostPID
}
