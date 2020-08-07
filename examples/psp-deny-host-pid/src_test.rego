package psp_deny_host_pid

test_hostpid_false {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "hostPID": false,
        }
    }

    not psp_allows_hostpid with input as input
}

test_hostpid_true {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "hostPID": true,
        }
    }

    psp_allows_hostpid with input as input
}
