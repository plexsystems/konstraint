package psp_deny_host_network

test_hostnetwork_false {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostNetwork": false},
	}

	not psp_allows_hostnetwork with input as input
}

test_hostnetwork_true {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostNetwork": true},
	}

	psp_allows_hostnetwork with input as input
}
