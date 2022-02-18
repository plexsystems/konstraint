package psp_deny_added_caps

test_dropped_all {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["all"]},
	}

	psp_dropped_all_capabilities with input as input
}

test_case_insensitivty {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["aLl"]},
	}

	psp_dropped_all_capabilities with input as input
}

test_null {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	}

	not psp_dropped_all_capabilities with input as input
}

test_dropped_none {
	input := {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["none"]},
	}

	not psp_dropped_all_capabilities with input as input
}
