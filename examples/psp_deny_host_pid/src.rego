# METADATA
# title: PodSecurityPolicies must not allow access to the host PID namespace
# description: |-
#   Allowing pods to access the host's process tree can view and attempt to
#   modify processes outside of their namespace, breaking that security
#   boundary.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - policy
#       kinds:
#       - PodSecurityPolicy
package psp_deny_host_pid

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1014"

violation contains msg if {
	psp_allows_hostpid

	msg = core.format_with_id(
		sprintf("%s/%s: Allows for sharing the host PID namespace", [core.kind, core.name]),
		policyID,
	)
}

psp_allows_hostpid if {
	psps.psps[_].spec.hostPID
}
