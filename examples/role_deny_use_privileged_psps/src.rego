# METADATA
# title: Roles must not allow use of privileged PodSecurityPolicies
# description: Workloads not running in the exempted namespaces must not use PodSecurityPolicies
#   with privileged permissions.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - rbac.authorization.k8s.io
#       kinds:
#       - Role
package role_deny_use_privileged_psps

import data.lib.core
import data.lib.rbac
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P2005"

violation contains msg if {
	role_uses_privileged_psp

	msg := core.format_with_id(
		sprintf("%s/%s: Allows using PodSecurityPolicies with privileged permissions", [core.kind, core.name]),
		policyID,
	)
}

role_uses_privileged_psp if {
	rule := core.resource.rules[_]
	rbac.rule_has_resource_type(rule, "podsecuritypolicies")
	rbac.rule_has_verb(rule, "use")
	rbac.rule_has_resource_name(rule, privileged_psps[_].metadata.name)
}

privileged_psps contains psp if {
	psp := data.inventory.cluster["policy/v1beta1"].PodSecurityPolicy[_]
	psp_is_privileged(psp)
}

psp_is_privileged(psp) if {
	psp.spec.privileged
}

psp_is_privileged(psp) if {
	security.added_capability(psp, "SYS_ADMIN")
}
