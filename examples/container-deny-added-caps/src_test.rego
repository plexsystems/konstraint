package container_deny_added_caps

test_dropped_all {
	container_dropped_all_capabilities({"securityContext": {"capabilities": {"drop": ["all"]}}})
}

test_dropped_none {
	not container_dropped_all_capabilities({"securityContext": {"capabilities": {"drop": ["none"]}}})
}
