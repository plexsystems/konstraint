# @title PodSecurityPolicies must require all capabilities are dropped
# 
# Allowing containers privileged capabilities on the node makes it easier
# for containers to escalate their privileges. As such, this is not allowed
# outside of Kubernetes controller namespaces.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_added_caps

import data.lib.core
import data.lib.psps
import data.lib.security

policyID := "P1009"

violation[msg] {
    not psp_dropped_all_capabilities

    msg := core.format(sprintf("%s/%s: Does not require droping all capabilities", [core.kind, core.name]), policyID)
}

psp_dropped_all_capabilities {
    psps.psps[psp]
    security.dropped_capability(psp, "all")
}
