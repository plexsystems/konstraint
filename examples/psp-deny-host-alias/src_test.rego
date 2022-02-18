package psp_deny_host_alias

test_hostaliases_false {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostAliases": false},
	}

	not psp_allows_hostaliases with input as input
}

test_hostaliases_true {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostAliases": true},
	}

	psp_allows_hostaliases with input as input
}
