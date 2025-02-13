package required_labels

import future.keywords.if

test_not_missing if {
	inp := {"metadata": {"labels": {"test": "test"}}}

	missing := missing_labels with input as inp
	count(missing) == 0
}

test_missing_gk if {
	inp := {
		"review": {"object": {"metadata": {"labels": {"test": "test"}}}},
		"parameters": {"labels": ["one", "two"]},
	}

	missing := missing_labels with input as inp
	count(missing) == 2
}
