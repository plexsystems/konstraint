package psp_deny_escalation

test_pos {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "allowPrivilegeEscalation": false
        }
    }

    violations := violation with input as input
    count(violations) == 0
}

test_null {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "a": "b"
        }
    }

    violations := violation with input as input
    count(violations) == 1
}

test_neg {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "allowPrivilegeEscalation": true
        }
    }

    violations := violation with input as input
    count(violations) == 1
}
