package container_deny_escalation

test_allowescalation_false {
	input := {"securityContext": {"allowPrivilegeEscalation": false}}

	not container_allows_escalation(input)
}

test_allowescalation_true {
	input := {"securityContext": {"allowPrivilegeEscalation": true}}

	container_allows_escalation(input)
}
