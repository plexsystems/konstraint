package lib.security

import future.keywords.if

test_added_capabilities_container_match if {
	added_capability({"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}}, "CAP_SYS_ADMIN")
}

test_added_capabilities_container_nomatch if {
	not added_capability({"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}}, "test")
}

test_added_capabilities_psp_match if {
	added_capability({"spec": {"allowedCapabilities": ["CAP_SYS_ADMIN"]}}, "CAP_SYS_ADMIN")
}

test_added_capabilities_psp_nomatch if {
	not added_capability({"spec": {"allowedCapabilities": ["CAP_SYS_ADMIN"]}}, "test")
}

test_dropped_capabilities_container_match if {
	dropped_capability({"securityContext": {"capabilities": {"drop": ["CAP_SYS_ADMIN"]}}}, "CAP_SYS_ADMIN")
}

test_dropped_capabilities_container_nomatch if {
	not dropped_capability({"securityContext": {"capabilities": {"drop": ["CAP_SYS_ADMIN"]}}}, "test")
}

test_dropped_capabilities_psp_match if {
	dropped_capability({"spec": {"requiredDropCapabilities": ["CAP_SYS_ADMIN"]}}, "CAP_SYS_ADMIN")
}

test_dropped_capabilities_psp_nomatch if {
	not dropped_capability({"spec": {"requiredDropCapabilities": ["CAP_SYS_ADMIN"]}}, "test")
}
