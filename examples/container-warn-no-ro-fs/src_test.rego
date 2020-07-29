package container_warn_no_ro_fs

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
                    "readOnlyRootFilesystem": true
                }
            }]
        }
    }
    warns := warn with input as input
    count(warns) == 0
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
                    "readOnlyRootFilesystem": false
                }
            }]
        }
    }
    warns := warn with input as input
    count(warns) == 1
}
