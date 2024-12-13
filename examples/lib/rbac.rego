package lib.rbac

import future.keywords.if
import future.keywords.in

import data.lib.core

rule_has_verb(rule, verb) if {
	verbs := ["*", lower(verb)]
	verbs[_] == lower(rule.verbs[_])
}

rule_has_resource_type(rule, type) if {
	types := ["*", lower(type)]
	types[_] == lower(rule.resources[_])
}

rule_has_resource_name(rule, name) if {
	name in rule.resourceNames
}

rule_has_resource_name(rule, _) if {
	core.missing_field(rule, "resourceNames")
}
