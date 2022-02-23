package pod_deny_without_runasnonroot

test_runasnonroot_true {
	input := {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"securityContext": {"runAsNonRoot": true}},
	}

	pod_runasnonroot with input as input
}

test_runasnonroot_null {
	input := {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
	}

	not pod_runasnonroot with input as input
}

test_runasnonroot_false {
	input := {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"securityContext": {"runAsNonRoot": false}},
	}

	not pod_runasnonroot with input as input
}
