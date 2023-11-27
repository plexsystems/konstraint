package psp_deny_host_alias

test_hostaliases_false {
	not psp_allows_hostaliases with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostAliases": false},
	}
}

test_hostaliases_true {
	psp_allows_hostaliases with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostAliases": true},
	}
}
