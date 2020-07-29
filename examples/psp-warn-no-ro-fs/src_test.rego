package psp_warn_no_ro_fs

test_happy {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "readOnlyRootFilesystem": true
        }
    }
    violations := warn with input as input
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
    violations := warn with input as input
    count(violations) == 1
}

test_neg {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "readOnlyRootFilesystem": false
        }
    }
    violations := warn with input as input
    count(violations) == 1
}
