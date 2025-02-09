package lib.rbac

import future.keywords.if

test_rule_has_verb_with_use if {
	rule_has_verb({"verbs": ["use"]}, "use")
}

test_rule_has_verb_with_asterisk if {
	rule_has_verb({"verbs": ["*"]}, "use")
}

test_rule_has_verb_with_list if {
	not rule_has_verb({"verbs": ["list"]}, "use")
}

test_rule_has_resource_type_with_pod if {
	rule_has_resource_type({"resources": ["Pod"]}, "pod")
}

test_rule_has_resource_type_with_resourceall if {
	rule_has_resource_type({"resources": ["*"]}, "pod")
}

test_rule_has_resource_type_with_container if {
	not rule_has_resource_type({"resources": ["Container"]}, "pod")
}

test_rule_has_resource_name_match if {
	rule_has_resource_name({"resourceNames": ["test"]}, "test")
}

test_rule_has_resource_name_no_match if {
	not rule_has_resource_name({"resourceNames": ["test"]}, "wrong")
}

test_rule_has_resource_name_null if {
	rule_has_resource_name({}, "wrong")
}
