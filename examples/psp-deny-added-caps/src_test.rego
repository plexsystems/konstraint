package psp_deny_added_caps

test_pos {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "requiredDropCapabilities": [
                "all"
            ],
        }
    }

    violations := violation with input as input
    count(violations) == 0
}

test_case_insensitivty {
    input := {
        "kind": "PodSecurityPolicy",
        "metadata": {
            "name": "test-psp"
        },
        "spec": {
            "requiredDropCapabilities": [
                "aLl"
            ],
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
            "requiredDropCapabilities": [
                "none"
            ],
        }
    }
    
    violations := violation with input as input
    count(violations) == 1
}
