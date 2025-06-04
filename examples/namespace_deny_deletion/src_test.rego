package namespace_deny_delete

import future.keywords.if

test_deny_namespace_delete_without_annotation if {
	not allow_namespace_deletion with input as {
		"kind": "Namespace",
		"metadata": {
			"name": "my-ns",
			"annotations": {},
		},
		"operation": "DELETE",
	}
}

test_allow_namespace_delete_with_annotation if {
	allow_namespace_deletion with input as {
		"kind": "Namespace",
		"metadata": {
			"name": "safe-ns",
			"annotations": {"allow-deletion": "true"},
		},
		"operation": "DELETE",
	}
}
