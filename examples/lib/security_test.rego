package lib.security

test_added_capabilities_container_match {
	added_capability({"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}}, "CAP_SYS_ADMIN")
}

test_added_capabilities_container_nomatch {
	not added_capability({"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}}, "test")
}

test_added_capabilities_psp_match {
	added_capability({"spec": {"allowedCapabilities": ["CAP_SYS_ADMIN"]}}, "CAP_SYS_ADMIN")
}

test_added_capabilities_psp_nomatch {
	not added_capability({"spec": {"allowedCapabilities": ["CAP_SYS_ADMIN"]}}, "test")
}

test_dropped_capabilities_container_match {
	dropped_capability({"securityContext": {"capabilities": {"drop": ["CAP_SYS_ADMIN"]}}}, "CAP_SYS_ADMIN")
}

test_dropped_capabilities_container_nomatch {
	not dropped_capability({"securityContext": {"capabilities": {"drop": ["CAP_SYS_ADMIN"]}}}, "test")
}

test_dropped_capabilities_psp_match {
	dropped_capability({"spec": {"requiredDropCapabilities": ["CAP_SYS_ADMIN"]}}, "CAP_SYS_ADMIN")
}

test_dropped_capabilities_psp_nomatch {
	not dropped_capability({"spec": {"requiredDropCapabilities": ["CAP_SYS_ADMIN"]}}, "test")
}
