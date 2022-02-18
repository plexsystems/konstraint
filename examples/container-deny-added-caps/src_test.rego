package container_deny_added_caps

test_dropped_all {
	input := {"securityContext": {"capabilities": {"drop": ["all"]}}}

	container_dropped_all_capabilities(input)
}

test_dropped_none {
	input := {"securityContext": {"capabilities": {"drop": ["none"]}}}

	not container_dropped_all_capabilities(input)
}
