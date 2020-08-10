package psp_deny_escalation

test_allowescalation_false {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "allowPrivilegeEscalation": false
        }
    }

    not allows_escalation(input)
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

    allows_escalation(input)
}

test_allowescalation_true {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "allowPrivilegeEscalation": true
        }
    }

    allows_escalation(input)
}
