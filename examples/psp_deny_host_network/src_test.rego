package psp_deny_host_network

import future.keywords.if

test_hostnetwork_false if {
	not psp_allows_hostnetwork with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostNetwork": false},
	}
}

test_hostnetwork_true if {
	psp_allows_hostnetwork with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostNetwork": true},
	}
}
