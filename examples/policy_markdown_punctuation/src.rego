# METADATA
# title: " Title   _wórds_ with-punct_uation_	!\"#$%&'()*+,./:;<=>?@[\\]^`{|}~mark "
# description: This is only here to test and illustrate _punctuation_ /
#   Markdown handling
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - "*"
#       kinds:
#       - Pod
#     labelSelector:
#       matchLabels:
#         _test_: "true"
#   parameters:
#     _param_name_:
#       type: array
#       items:
#         type: string
package policy_markdown_punctuation

import data.lib.core
import future.keywords.contains
import future.keywords.if

policyID := "P0003"

warn contains msg if {
	core.apiVersion == "foo/bar"
	msg := core.format_with_id("Title tester", policyID)
}
