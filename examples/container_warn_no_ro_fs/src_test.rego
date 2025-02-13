package container_warn_no_ro_fs

import future.keywords.if

test_rofs_true if {
	not no_read_only_filesystem({"securityContext": {"readOnlyRootFilesystem": true}})
}

test_rofs_false if {
	no_read_only_filesystem({"securityContext": {"readOnlyRootFilesystem": false}})
}
