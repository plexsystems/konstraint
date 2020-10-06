# @title PodSecurityPolicies must not allow privileged escalation
# 
# Allowing privileged containers can much more easily obtain root on the node.
# As such, they are not allowed.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_escalation

import data.lib.core
import data.lib.psps

policyID := "P1010"

violation[msg] {
    psps.psps[psp]
    allows_escalation(psp)

    msg := core.format_with_id(sprintf("%s/%s: Allows privilege escalation", [core.kind, core.name]), policyID)
}

allows_escalation(p) {
    p.spec.allowPrivilegeEscalation == true
}

allows_escalation(p) {
    core.missing_field(p.spec, "allowPrivilegeEscalation")
}
