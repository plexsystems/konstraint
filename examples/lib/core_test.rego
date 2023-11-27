package lib.core

test_not_gk {
	not is_gatekeeper with input as {"kind": "test"}
}

test_is_gk {
	is_gatekeeper with input as {"review": {"object": {"kind": "test"}}}
}

test_has_field_pos {
	has_field({"kind": "test"}, "kind")
}

test_missing_field {
	not has_field({"kind": "test"}, "abc")
}
