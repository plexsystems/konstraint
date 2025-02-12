package psp_deny_host_ipc

import future.keywords.if

test_hostipc_false if {
	not psp_allows_hostipc with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostIPC": false},
	}
}

test_hostipc_true if {
	psp_allows_hostipc with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostIPC": true},
	}
}
