package psp_deny_host_pid

test_pos {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
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
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "hostPID": true,
        }
    }

    violations := violation with input as input
    count(violations) == 1
}
