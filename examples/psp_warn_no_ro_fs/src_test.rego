package psp_warn_no_ro_fs

import future.keywords.if

test_rofs_true if {
	not no_read_only_filesystem({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"readOnlyRootFilesystem": true},
	})
}

test_null if {
	no_read_only_filesystem({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	})
}

test_rofs_false if {
	no_read_only_filesystem({
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"readOnlyRootFilesystem": false},
	})
}
