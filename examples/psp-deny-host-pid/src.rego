# @title PodSecurityPolicies must not allow access to the host PID namespace
# 
# Allowing pods to acess the host's process tree can view and attempt to
# modify processes outside of their namespace, breaking that security
# boundary.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_host_pid

import data.lib.core
import data.lib.psps

violation[msg] {
    psp_allows_hostpid
    
    msg = core.format(sprintf("%s/%s: Allows for sharing the host PID namespace", [core.kind, core.name]))
}

psp_allows_hostpid {
    psps.psps[_].spec.hostPID
}
