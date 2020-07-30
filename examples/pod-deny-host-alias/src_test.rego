package pod_deny_host_alias

test_pos {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostAliases": false,
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
            "hostAliases": true,
        }
    }
    violations := violation with input as input
    count(violations) == 1
}
