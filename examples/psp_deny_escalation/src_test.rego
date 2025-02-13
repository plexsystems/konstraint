package psp_deny_escalation

import future.keywords.if

test_allowescalation_false if {
	not allows_escalation({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"allowPrivilegeEscalation": false},
	})
}

test_null if {
	allows_escalation({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	})
}

test_allowescalation_true if {
	allows_escalation({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"allowPrivilegeEscalation": true},
	})
}
