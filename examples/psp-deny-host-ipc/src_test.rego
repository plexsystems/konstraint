package psp_deny_host_ipc

test_hostipc_false {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostIPC": false},
	}

	not psp_allows_hostipc with input as input
}

test_hostipc_true {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostIPC": true},
	}

	psp_allows_hostipc with input as input
}
