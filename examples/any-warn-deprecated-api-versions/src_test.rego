package any_warn_deprecated_api_versions

test_matching {
	input := {
		"kind": "Deployment",
		"metadata": {"name": "test"},
		"apiVersion": "extensions/v1beta1",
	}

	warns := warn with input as input
	count(warns) == 1
}

test_different_kind {
	input := {
		"kind": "test",
		"metadata": {"name": "test"},
		"apiVersion": "extensions/v1beta1",
	}

	warns := warn with input as input
	count(warns) == 0
}

test_different_apiversion {
	input := {
		"kind": "Deployment",
		"metadata": {"name": "test"},
		"apiVersion": "test",
	}

	warns := warn with input as input
	count(warns) == 0
}
