package psp_deny_privileged

test_privileged_false {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"privileged": false},
	}

	not psp_allows_privileged with input as input
}

test_privileged_true {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"privileged": true},
	}

	psp_allows_privileged with input as input
}
