package container_deny_privileged

import future.keywords.if

test_privileged_true if {
	container_is_privileged({"securityContext": {"privileged": true}})
}

test_privileged_false if {
	not container_is_privileged({"securityContext": {"privileged": false}})
}

test_added_capability if {
	container_is_privileged({"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}})
}
