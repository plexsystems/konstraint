package policy_markdown_punctuation

import future.keywords.if

test_ignoreme if {
	count(warn) == 1 with input as {"apiVersion": "foo/bar"}
}
