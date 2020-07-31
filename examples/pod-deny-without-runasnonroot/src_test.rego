package pod_deny_without_runasnonroot

test_pos {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "securityContext": {
                "runAsNonRoot": true
            }
        }
    }

    violations := violation with input as input
    count(violations) == 0
}

test_null {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "securityContext": {}
        }
    }

    violations := violation with input as input
    count(violations) == 1
}

test_neg {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "securityContext": {
                "runAsNonRoot": false
            }
        }
    }
    
    violations := violation with input as input
    count(violations) == 1
}
