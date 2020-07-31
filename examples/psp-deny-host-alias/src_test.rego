package psp_deny_host_alias

test_pos {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
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
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "hostAliases": true,
        }
    }

    violations := violation with input as input
    count(violations) == 1
}
