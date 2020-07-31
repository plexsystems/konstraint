package psp_deny_host_network

test_pos {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
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
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "hostNetwork": true,
        }
    }

    violations := violation with input as input
    count(violations) == 1
}
