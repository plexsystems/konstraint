# METADATA
# title: Containers should not have a writable root filesystem
# description: |-
#   In order to prevent persistence in the case of a compromise, it is
#   important to make the root filesystem read-only.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - ""
#       kinds:
#       - Pod
#     - apiGroups:
#       - apps
#       kinds:
#       - DaemonSet
#       - Deployment
#       - StatefulSet
package container_warn_no_ro_fs

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P2003"

warn contains msg if {
	some container
	pods.containers[container]
	no_read_only_filesystem(container)

	msg := core.format_with_id(
		sprintf("%s/%s/%s: Is not using a read only root filesystem", [core.kind, core.name, container.name]),
		policyID,
	)
}

no_read_only_filesystem(container) if {
	core.has_field(container.securityContext, "readOnlyRootFilesystem")
	not container.securityContext.readOnlyRootFilesystem
}

no_read_only_filesystem(container) if {
	core.missing_field(container.securityContext, "readOnlyRootFilesystem")
}
