package pod_deny_host_network

test_pos {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostNetwork": false,
        }
    }
    
    violations := violation with input as input
    count(violations) == 0
}

test_neg {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostNetwork": true,
        }
    }

    violations := violation with input as input
    count(violations) == 1
}
