package pod_deny_host_network

test_hostnetwork_false {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostNetwork": false,
        }
    }

    not pod_has_hostnetwork with input as input
}

test_hostnetwork_true {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostNetwork": true,
        }
    }

    pod_has_hostnetwork with input as input
}
