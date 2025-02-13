package container_deny_added_caps

import future.keywords.if

test_dropped_all if {
	container_dropped_all_capabilities({"securityContext": {"capabilities": {"drop": ["all"]}}})
}

test_dropped_none if {
	not container_dropped_all_capabilities({"securityContext": {"capabilities": {"drop": ["none"]}}})
}
