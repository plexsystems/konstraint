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

policyID := "P1015"

violation[msg] {
	psp_allows_privileged

	msg := core.format_with_id(sprintf("%s/%s: Allows for privileged workloads", [core.kind, core.name]), policyID)
}

psp_allows_privileged {
	psps.psps[_].spec.privileged
}
