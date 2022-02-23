package container_warn_no_ro_fs

test_rofs_true {
	input := {"securityContext": {"readOnlyRootFilesystem": true}}

	not no_read_only_filesystem(input)
}

test_rofs_false {
	input := {"securityContext": {"readOnlyRootFilesystem": false}}

	no_read_only_filesystem(input)
}
