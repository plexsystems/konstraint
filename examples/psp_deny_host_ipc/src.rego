# METADATA
# title: PodSecurityPolicies must not allow access to the host IPC
# description: |-
#   Allowing pods to access the host IPC can read memory of
#   the other containers, breaking that security boundary.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - policy
#       kinds:
#       - PodSecurityPolicy
package psp_deny_host_ipc

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1012"

violation contains msg if {
	psp_allows_hostipc

	msg := core.format_with_id(
		sprintf("%s/%s: Allows for sharing the host IPC namespace", [core.kind, core.name]),
		policyID,
	)
}

psp_allows_hostipc if {
	psps.psps[_].spec.hostIPC
}
