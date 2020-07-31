package psp_deny_host_ipc

test_pos {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "hostIPC": false,
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
            "hostIPC": true,
        }
    }
    
    violations := violation with input as input
    count(violations) == 1
}
