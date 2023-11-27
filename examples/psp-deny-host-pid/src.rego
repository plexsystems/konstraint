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

policyID := "P1014"

violation[msg] {
	psp_allows_hostpid

	msg = core.format_with_id(
		sprintf("%s/%s: Allows for sharing the host PID namespace", [core.kind, core.name]),
		policyID,
	)
}

psp_allows_hostpid {
	psps.psps[_].spec.hostPID
}
