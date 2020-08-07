package pod_deny_host_pid

test_hostpid_false {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostPID": false,
        }
    }

    not pod_has_hostpid with input as input
}

test_hostpid_true {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostPID": true,
        }
    }

    pod_has_hostpid with input as input
}
