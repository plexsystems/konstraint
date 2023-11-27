package pod_deny_host_ipc

test_hostipc_false {
	not pod_has_hostipc with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostIPC": false},
	}
}

test_hostipc_true {
	pod_has_hostipc with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostIPC": true},
	}
}
