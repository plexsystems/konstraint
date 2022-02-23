# @title PodSecurityPolicies must not allow access to the host aliases
# 
# Allowing pods to can change aliases in the host's /etc/hosts file can 
# redirect traffic to malicious servers.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_host_alias

import data.lib.core
import data.lib.psps

policyID := "P1011"

violation[msg] {
	psp_allows_hostaliases

	msg := core.format_with_id(sprintf("%s/%s: Allows for managing host aliases", [core.kind, core.name]), policyID)
}

psp_allows_hostaliases {
	psps.psps[_].spec.hostAliases
}
