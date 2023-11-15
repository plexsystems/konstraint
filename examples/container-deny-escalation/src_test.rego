package container_deny_escalation

test_allowescalation_false {
	not container_allows_escalation({"securityContext": {"allowPrivilegeEscalation": false}})
}

test_allowescalation_true {
	container_allows_escalation({"securityContext": {"allowPrivilegeEscalation": true}})
}
