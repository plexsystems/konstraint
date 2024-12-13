package lib.core

import future.keywords.if

test_not_gk if {
	not is_gatekeeper with input as {"kind": "test"}
}

test_is_gk if {
	is_gatekeeper with input as {"review": {"object": {"kind": "test"}}}
}

test_has_field_pos if {
	has_field({"kind": "test"}, "kind")
}

test_missing_field if {
	not has_field({"kind": "test"}, "abc")
}
