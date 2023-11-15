package psp_deny_host_network

test_hostnetwork_false {
	not psp_allows_hostnetwork with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostNetwork": false},
	}
}

test_hostnetwork_true {
	psp_allows_hostnetwork with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostNetwork": true},
	}
}
