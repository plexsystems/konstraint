# METADATA
# title: Required Labels
# description: >-
#  This policy allows you to require certain labels are set on a resource.
#  Adapted from https://github.com/open-policy-agent/gatekeeper/blob/master/example/templates/k8srequiredlabels_template.yaml
# custom:
#   parameters:
#     labels:
#       type: array
#       description: Array of required label keys.
#       items:
#         type: string
package required_labels

import data.lib.core

policyID := "P0002"

violation[msg] {
	missing := missing_labels
	count(missing) > 0

	msg := core.format_with_id(sprintf("%s/%s: Missing required labels: %v", [core.kind, core.name, missing]), policyID)
}

missing_labels := missing {
	provided := {label | core.labels[label]}
	required := {label | label := input.parameters.labels[_]}
	missing := required - provided
}
