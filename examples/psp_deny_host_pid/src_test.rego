package psp_deny_host_pid

import future.keywords.if

test_hostpid_false if {
	not psp_allows_hostpid with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostPID": false},
	}
}

test_hostpid_true if {
	psp_allows_hostpid with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostPID": true},
	}
}
