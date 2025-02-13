package pod_deny_host_alias

import future.keywords.if

test_input_with_alias_missing if {
	not pod_host_alias with input as {"kind": "Pod"}
}

test_input_with_alias if {
	pod_host_alias with input as {
		"kind": "Pod",
		"spec": {"hostAliases": [{"ip": "127.0.0.1", "hostnames": ["foo.local"]}]},
	}
}
