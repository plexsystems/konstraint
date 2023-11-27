package psp_deny_added_caps

test_dropped_all {
	psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["all"]},
	}
}

test_case_insensitivty {
	psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["aLl"]},
	}
}

test_null {
	not psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	}
}

test_dropped_none {
	not psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["none"]},
	}
}
