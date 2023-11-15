package container_warn_no_ro_fs

test_rofs_true {
	not no_read_only_filesystem({"securityContext": {"readOnlyRootFilesystem": true}})
}

test_rofs_false {
	no_read_only_filesystem({"securityContext": {"readOnlyRootFilesystem": false}})
}
