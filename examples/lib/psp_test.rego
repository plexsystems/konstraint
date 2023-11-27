package lib.psps

test_exception_pos {
	is_exception with input as {"metadata": {"name": "gce.privileged"}}
}

test_exception_neg {
	not is_exception with input as {"metadata": {"name": "test"}}
}
