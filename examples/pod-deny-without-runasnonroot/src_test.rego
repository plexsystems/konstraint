package pod_deny_without_runasnonroot

test_runasnonroot_true {
	pod_runasnonroot with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"securityContext": {"runAsNonRoot": true}},
	}
}

test_runasnonroot_null {
	not pod_runasnonroot with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
	}
}

test_runasnonroot_false {
	not pod_runasnonroot with input as {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"securityContext": {"runAsNonRoot": false}},
	}
}
