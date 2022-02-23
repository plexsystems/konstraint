package pod_deny_host_alias

test_input_with_alias_missing {
	input := {
		"kind": "Pod",
		"spec": {},
	}

	not pod_host_alias with input as input
}

test_input_with_alias {
	input := {
		"kind": "Pod",
		"spec": {"hostAliases": [{"ip": "127.0.0.1", "hostnames": ["foo.local"]}]},
	}

	pod_host_alias with input as input
}
