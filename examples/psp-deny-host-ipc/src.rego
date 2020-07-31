# @title PodSecurityPolicies must not allow access to the host IPC
# 
# Allowing pods to to access the host IPC can read memory of
# the other containers, breaking that security boundary.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_host_ipc

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.hostIPC

    msg := core.format(sprintf("%s/%s: Allows for sharing the host IPC namespace", [core.kind, core.name]))
}
