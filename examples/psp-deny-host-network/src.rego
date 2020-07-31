# @title PodSecurityPolicies must not allow access to the host network
# 
# Allowing pods to acess the host's process tree can view and attempt to
# modify processes outside of their namespace, breaking that security
# boundary.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_host_network

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.hostNetwork

    msg := core.format(sprintf("%s/%s: Allows for accessing the host network", [core.kind, core.name]))
}
