# @title PodSecurityPolicies must require containers to not run as privileged
# 
# Allowing privileged containers can much more easily obtain root on the node.
# As such, they are not allowed.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_privileged

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.privileged
    
    msg := core.format(sprintf("%s/%s: Allows for privileged workloads", [core.kind, core.name]))
}
