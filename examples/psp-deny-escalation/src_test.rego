package psp_deny_escalation

test_allowescalation_false {
	not allows_escalation({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"allowPrivilegeEscalation": false},
	})
}

test_null {
	allows_escalation({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	})
}

test_allowescalation_true {
	allows_escalation({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"allowPrivilegeEscalation": true},
	})
}
