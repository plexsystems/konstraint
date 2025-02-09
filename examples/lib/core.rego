package lib.core

import future.keywords.if

default is_gatekeeper := false

is_gatekeeper if {
	has_field(input, "review")
	has_field(input.review, "object")
}

resource := input.review.object if {
	is_gatekeeper
}

resource := input if {
	not is_gatekeeper
}

format(msg) := {"msg": msg}

format_with_id(msg, id) := {
	"msg": sprintf("%s: %s", [id, msg]),
	"details": {"policyID": id},
}

apiVersion := resource.apiVersion

name := resource.metadata.name

kind := resource.kind

labels := resource.metadata.labels

annotations := resource.metadata.annotations

gv := split(apiVersion, "/")

group := gv[0] if {
	contains(apiVersion, "/")
}

group := "core" if {
	not contains(apiVersion, "/")
}

version := gv[count(gv) - 1]

has_field(obj, field) if {
	not object.get(obj, field, "N_DEFINED") == "N_DEFINED"
}

missing_field(obj, field) if {
	obj[field] == ""
}

missing_field(obj, field) if {
	not has_field(obj, field)
}
