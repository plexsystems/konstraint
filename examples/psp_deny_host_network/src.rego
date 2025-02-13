# METADATA
# title: PodSecurityPolicies must not allow access to the host network
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
package psp_deny_host_network

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1013"

violation contains msg if {
	psp_allows_hostnetwork

	msg := core.format_with_id(sprintf("%s/%s: Allows for accessing the host network", [core.kind, core.name]), policyID)
}

psp_allows_hostnetwork if {
	psps.psps[_].spec.hostNetwork
}
