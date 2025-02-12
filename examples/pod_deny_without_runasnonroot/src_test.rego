package pod_deny_without_runasnonroot

import future.keywords.if

test_runasnonroot_true if {
	pod_runasnonroot with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"securityContext": {"runAsNonRoot": true}},
	}
}

test_runasnonroot_null if {
	not pod_runasnonroot with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
	}
}

test_runasnonroot_false if {
	not pod_runasnonroot with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"securityContext": {"runAsNonRoot": false}},
	}
}
