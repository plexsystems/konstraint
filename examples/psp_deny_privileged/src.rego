# METADATA
# title: PodSecurityPolicies must require containers to not run as privileged
# description: |-
#   Allowing privileged containers can much more easily obtain root on the node.
#   As such, they are not allowed.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - policy
#       kinds:
#       - PodSecurityPolicy
package psp_deny_privileged

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1015"

violation contains msg if {
	psp_allows_privileged

	msg := core.format_with_id(sprintf("%s/%s: Allows for privileged workloads", [core.kind, core.name]), policyID)
}

psp_allows_privileged if {
	psps.psps[_].spec.privileged
}
