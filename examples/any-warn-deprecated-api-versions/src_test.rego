package any_warn_deprecated_api_versions

test_matching {
	warns := warn with input as {
		"kind": "Deployment",
		"metadata": {"name": "test"},
		"apiVersion": "extensions/v1beta1",
	}
	count(warns) == 1
}

test_different_kind {
	warns := warn with input as {
		"kind": "test",
		"metadata": {"name": "test"},
		"apiVersion": "extensions/v1beta1",
	}
	count(warns) == 0
}

test_different_apiversion {
	warns := warn with input as {
		"kind": "Deployment",
		"metadata": {"name": "test"},
		"apiVersion": "test",
	}
	count(warns) == 0
}
