package pod_deny_host_alias

test_input_with_alias_missing {
	not pod_host_alias with input as {"kind": "Pod"}
}

test_input_with_alias {
	pod_host_alias with input as {
		"kind": "Pod",
		"spec": {"hostAliases": [{"ip": "127.0.0.1", "hostnames": ["foo.local"]}]},
	}
}
