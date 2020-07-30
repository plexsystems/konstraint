package psp_deny_privileged

test_pos {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "privileged": false,
        }
    }
    violations := violation with input as input
    count(violations) == 0
}

test_neg {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "privileged": true,
        }
    }
    violations := violation with input as input
    count(violations) == 1
}

