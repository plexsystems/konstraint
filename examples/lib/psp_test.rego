package lib.psps

import future.keywords.if

test_exception_pos if {
	is_exception with input as {"metadata": {"name": "gce.privileged"}}
}

test_exception_neg if {
	not is_exception with input as {"metadata": {"name": "test"}}
}
