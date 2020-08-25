package role_deny_use_privileged_psps

test_role_uses_privileged_psp_match {
    input := {
        "rules": [{
            "resourceNames": ["test"],
            "resources": ["podsecuritypolicies"],
            "verbs": ["use"]
        }]
    }

    role_uses_privileged_psp with input as input
}

test_role_uses_privileged_psp_wildcard_verb {
    input := {
        "rules": [{
            "resourceNames": ["test"],
            "resources": ["podsecuritypolicies"],
            "verbs": ["*"]
        }]
    }

    role_uses_privileged_psp with input as input
}

test_role_uses_privileged_psp_no_resource_names {
    input := {
        "rules": [{
            "resources": ["podsecuritypolicies"],
            "verbs": ["use"]
        }]
    }

    role_uses_privileged_psp with input as input
}

test_role_uses_privileged_psp_wrong_name {
    input := {
        "rules": [{
            "resourceNames": ["wrong"],
            "resources": ["podsecuritypolicies"],
            "verbs": ["use"]
        }]
    }

    not role_uses_privileged_psp with input as input
}

test_role_uses_privileged_psp_wrong_resource_type {
    input := {
        "rules": [{
            "resourceNames": ["test"],
            "resources": ["wrong"],
            "verbs": ["use"]
        }]
    }

    not role_uses_privileged_psp with input as input
}

test_role_uses_privileged_psp_wrong_verb {
    input := {
        "rules": [{
            "resourceNames": ["test"],
            "resources": ["podsecuritypolicies"],
            "verbs": ["wrong"]
        }]
    }

    not role_uses_privileged_psp with input as input
}
