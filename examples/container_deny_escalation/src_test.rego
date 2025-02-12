package container_deny_escalation

import future.keywords.if

test_allowescalation_false if {
	not container_allows_escalation({"securityContext": {"allowPrivilegeEscalation": false}})
}

test_allowescalation_true if {
	container_allows_escalation({"securityContext": {"allowPrivilegeEscalation": true}})
}
