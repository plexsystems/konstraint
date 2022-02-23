package psp_warn_no_ro_fs

test_rofs_true {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"readOnlyRootFilesystem": true},
	}

	not no_read_only_filesystem(input)
}

test_null {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	}

	no_read_only_filesystem(input)
}

test_rofs_false {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"readOnlyRootFilesystem": false},
	}

	no_read_only_filesystem(input)
}
