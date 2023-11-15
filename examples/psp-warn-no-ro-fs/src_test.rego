package psp_warn_no_ro_fs

test_rofs_true {
	not no_read_only_filesystem({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"readOnlyRootFilesystem": true},
	})
}

test_null {
	no_read_only_filesystem({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	})
}

test_rofs_false {
	no_read_only_filesystem({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"readOnlyRootFilesystem": false},
	})
}
