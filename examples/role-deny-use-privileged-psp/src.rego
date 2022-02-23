# @title Roles must not allow use of privileged PodSecurityPolicies
# 
# Workloads not running in the exempted namespaces must not use PodSecurityPolicies with privileged permissions.
#
# @kinds rbac.authorization.k8s.io/Role
package role_deny_use_privileged_psps

import data.lib.core
import data.lib.rbac
import data.lib.security

policyID := "P2005"

violation[msg] {
	role_uses_privileged_psp

	msg := core.format_with_id(sprintf("%s/%s: Allows using PodSecurityPolicies with privileged permissions", [core.kind, core.name]), policyID)
}

role_uses_privileged_psp {
	rule := core.resource.rules[_]
	rbac.rule_has_resource_type(rule, "podsecuritypolicies")
	rbac.rule_has_verb(rule, "use")
	rbac.rule_has_resource_name(rule, privileged_psps[_].metadata.name)
}

privileged_psps[psp] {
	psp := data.inventory.cluster["policy/v1beta1"].PodSecurityPolicy[_]
	psp_is_privileged(psp)
}

psp_is_privileged(psp) {
	psp.spec.privileged
}

psp_is_privileged(psp) {
	security.added_capability(psp, "SYS_ADMIN")
}
