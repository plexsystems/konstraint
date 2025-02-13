# METADATA
# title: PodSecurityPolicies should require that a read-only root filesystem is set
# description: |-
#   Allowing pods to access the host's network interfaces can potentially
#   access and tamper with traffic the pod should not have access to.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - policy
#       kinds:
#       - PodSecurityPolicy
package psp_warn_no_ro_fs

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P2004"

warn contains msg if {
	some psp
	psps.psps[psp]
	no_read_only_filesystem(psp)

	msg := core.format_with_id(sprintf("%s/%s: Allows for a writeable root filesystem", [core.kind, core.name]), policyID)
}

no_read_only_filesystem(psp) if {
	core.missing_field(psp.spec, "readOnlyRootFilesystem")
}

no_read_only_filesystem(psp) if {
	not psp.spec.readOnlyRootFilesystem
}
