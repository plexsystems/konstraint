package pod_deny_host_pid

import future.keywords.if

test_hostpid_false if {
	not pod_has_hostpid with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostPID": false},
	}
}

test_hostpid_true if {
	pod_has_hostpid with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostPID": true},
	}
}
