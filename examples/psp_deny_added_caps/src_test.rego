package psp_deny_added_caps

import future.keywords.if

test_dropped_all if {
	psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["all"]},
	}
}

test_case_insensitivty if {
	psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["aLl"]},
	}
}

test_null if {
	not psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"a": "b"},
	}
}

test_dropped_none if {
	not psp_dropped_all_capabilities with input as {
		"kind": "PodSecurityPolicy",
		"metadata": {"name": "test-psp"},
		"spec": {"requiredDropCapabilities": ["none"]},
	}
}
