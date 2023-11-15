package psp_deny_host_pid

test_hostpid_false {
	not psp_allows_hostpid with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostPID": false},
	}
}

test_hostpid_true {
	psp_allows_hostpid with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostPID": true},
	}
}
