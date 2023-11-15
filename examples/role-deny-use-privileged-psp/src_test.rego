package role_deny_use_privileged_psps

test_role_uses_privileged_psp_match {
	role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wildcard_verb {
	role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["*"],
	}]}
}

test_role_uses_privileged_psp_no_resource_names {
	role_uses_privileged_psp with input as {"rules": [{
		"resources": ["podsecuritypolicies"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wrong_name {
	not role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["wrong"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wrong_resource_type {
	not role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["wrong"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wrong_verb {
	not role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["wrong"],
	}]}
}
