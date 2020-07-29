package container_deny_added_caps

test_pos {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "containers": [{
                "name": "test-container",
                "securityContext": {
                    "capabilities": {
                        "drop": ["alL"]
                    }
                }
            }]
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
            "containers": [{
                "name": "test-container",
                "securityContext": {
                    "capabilities": {
                        "drop": ["none"]
                    }
                }
            }]
        }
    }
    violations := violation with input as input
    count(violations) == 1
}
