package any_warn_deprecated_api_versions

import future.keywords.if

test_matching if {
	warns := warn with input as {
		"kind": "Deployment",
		"metadata": {"name": "test"},
		"apiVersion": "extensions/v1beta1",
	}
	count(warns) == 1
}

test_different_kind if {
	warns := warn with input as {
		"kind": "test",
		"metadata": {"name": "test"},
		"apiVersion": "extensions/v1beta1",
	}
	count(warns) == 0
}

test_different_apiversion if {
	warns := warn with input as {
		"kind": "Deployment",
		"metadata": {"name": "test"},
		"apiVersion": "test",
	}
	count(warns) == 0
}
