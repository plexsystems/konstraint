# METADATA
# title: Namespace deletion must be denied unless explicitly allowed
# description: >-
#   Prevent deletion of Kubernetes namespaces to avoid accidental or unauthorized removal of critical workloads.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - ""
#       kinds:
#       - Namespace
package namespace_deny_delete

import data.lib.core
import future.keywords.contains
import future.keywords.if
import future.keywords.if

policyID := "P2007"

violation contains msg if {
	core.kind == "Namespace"
	core.operation == "DELETE"
	not allow_namespace_deletion

	msg := core.format_with_id(sprintf("%s/%s: Deletion of Namespace is not allowed", [core.kind, core.name]), policyID)
}

allow_namespace_deletion if {
	core.annotations["allow-deletion"] == "true"
}
