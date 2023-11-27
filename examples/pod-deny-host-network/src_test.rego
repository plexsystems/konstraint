package pod_deny_host_network

test_hostnetwork_false {
	not pod_has_hostnetwork with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostNetwork": false},
	}
}

test_hostnetwork_true {
	pod_has_hostnetwork with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostNetwork": true},
	}
}
