package psp_deny_privileged

test_privileged_false {
	not psp_allows_privileged with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"privileged": false},
	}
}

test_privileged_true {
	psp_allows_privileged with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"privileged": true},
	}
}
