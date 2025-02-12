package role_deny_use_privileged_psps

import future.keywords.if

test_role_uses_privileged_psp_match if {
	role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wildcard_verb if {
	role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["*"],
	}]}
}

test_role_uses_privileged_psp_no_resource_names if {
	role_uses_privileged_psp with input as {"rules": [{
		"resources": ["podsecuritypolicies"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wrong_name if {
	not role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["wrong"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wrong_resource_type if {
	not role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["wrong"],
		"verbs": ["use"],
	}]}
}

test_role_uses_privileged_psp_wrong_verb if {
	not role_uses_privileged_psp with input as {"rules": [{
		"resourceNames": ["test"],
		"resources": ["podsecuritypolicies"],
		"verbs": ["wrong"],
	}]}
}
