package pod_deny_host_ipc

import future.keywords.if

test_hostipc_false if {
	not pod_has_hostipc with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostIPC": false},
	}
}

test_hostipc_true if {
	pod_has_hostipc with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostIPC": true},
	}
}
