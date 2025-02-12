# METADATA
# title: PodSecurityPolicies must not allow access to the host aliases
# description: |-
#   Allowing pods to can change aliases in the host's /etc/hosts file can
#   redirect traffic to malicious servers.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - policy
#       kinds:
#       - PodSecurityPolicy
package psp_deny_host_alias

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1011"

violation contains msg if {
	psp_allows_hostaliases

	msg := core.format_with_id(sprintf("%s/%s: Allows for managing host aliases", [core.kind, core.name]), policyID)
}

psp_allows_hostaliases if {
	psps.psps[_].spec.hostAliases
}
