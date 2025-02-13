package psp_deny_host_alias

import future.keywords.if

test_hostaliases_false if {
	not psp_allows_hostaliases with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostAliases": false},
	}
}

test_hostaliases_true if {
	psp_allows_hostaliases with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostAliases": true},
	}
}
