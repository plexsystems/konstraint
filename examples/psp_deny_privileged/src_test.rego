package psp_deny_privileged

import future.keywords.if

test_privileged_false if {
	not psp_allows_privileged with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"privileged": false},
	}
}

test_privileged_true if {
	psp_allows_privileged with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"privileged": true},
	}
}
