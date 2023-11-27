package psp_deny_host_ipc

test_hostipc_false {
	not psp_allows_hostipc with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostIPC": false},
	}
}

test_hostipc_true {
	psp_allows_hostipc with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"hostIPC": true},
	}
}
