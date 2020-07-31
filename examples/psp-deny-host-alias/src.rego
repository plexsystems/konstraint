# @title PodSecurityPolicies must not allow access to the host aliases
# 
# Allowing pods to can change aliases in the host's /etc/hosts file can 
# redirect traffic to malicious servers.
#
# @kinds policy/PodSecurityPolicy
package psp_deny_host_alias

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.hostAliases

    msg := core.format(sprintf("%s/%s: Allows for managing host aliases", [core.kind, core.name]))
}
