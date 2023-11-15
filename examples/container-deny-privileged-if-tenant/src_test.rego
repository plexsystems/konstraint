package container_deny_privileged

test_privileged_true {
	container_is_privileged({"securityContext": {"privileged": true}})
}

test_privileged_false {
	not container_is_privileged({"securityContext": {"privileged": false}})
}

test_added_capability {
	container_is_privileged({"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}}})
}
