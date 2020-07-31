package container_deny_escalation

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
                    "allowPrivilegeEscalation": false
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
                    "allowPrivilegeEscalation": true
                }
            }]
        }
    }
    
    violations := violation with input as input
    count(violations) == 1
}
