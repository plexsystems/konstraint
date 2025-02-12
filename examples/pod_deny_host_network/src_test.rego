package pod_deny_host_network

import future.keywords.if

test_hostnetwork_false if {
	not pod_has_hostnetwork with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostNetwork": false},
	}
}

test_hostnetwork_true if {
	pod_has_hostnetwork with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"hostNetwork": true},
	}
}
