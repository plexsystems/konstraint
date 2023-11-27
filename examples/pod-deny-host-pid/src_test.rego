package pod_deny_host_pid

test_hostpid_false {
	not pod_has_hostpid with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostPID": false},
	}
}

test_hostpid_true {
	pod_has_hostpid with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostPID": true},
	}
}
