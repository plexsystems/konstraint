package lib.rbac

test_rule_has_verb_with_use {
	rule_has_verb({"verbs": ["use"]}, "use")
}

test_rule_has_verb_with_asterisk {
	rule_has_verb({"verbs": ["*"]}, "use")
}

test_rule_has_verb_with_list {
	not rule_has_verb({"verbs": ["list"]}, "use")
}

test_rule_has_resource_type_with_pod {
	rule_has_resource_type({"resources": ["Pod"]}, "pod")
}

test_rule_has_resource_type_with_resourceall {
	rule_has_resource_type({"resources": ["*"]}, "pod")
}

test_rule_has_resource_type_with_container {
	not rule_has_resource_type({"resources": ["Container"]}, "pod")
}

test_rule_has_resource_name_match {
	rule_has_resource_name({"resourceNames": ["test"]}, "test")
}

test_rule_has_resource_name_no_match {
	not rule_has_resource_name({"resourceNames": ["test"]}, "wrong")
}

test_rule_has_resource_name_null {
	rule_has_resource_name({}, "wrong")
}
