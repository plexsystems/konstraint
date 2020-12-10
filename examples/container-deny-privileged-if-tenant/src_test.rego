package container_deny_privileged

test_privileged_true {
    input := {"securityContext": {"privileged": true}}

    container_is_privileged(input)
}

test_privileged_false {
    input := {"securityContext": {"privileged": false}}

    not container_is_privileged(input)
}

test_added_capability {
    input := {
        "securityContext": {
            "capabilities": {"add": ["CAP_SYS_ADMIN"]}
        }
    }

    container_is_privileged(input)
}
