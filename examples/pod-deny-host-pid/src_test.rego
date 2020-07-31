package pod_deny_host_pid

test_pos {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostPID": false,
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
            "hostPID": true,
        }
    }
    
    violations := violation with input as input
    count(violations) == 1
}
