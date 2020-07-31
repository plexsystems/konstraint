package lib.core

default is_gatekeeper = false

is_gatekeeper {
    has_field(input, "review")
    has_field(input.review, "object")
}

resource = input.review.object {
    is_gatekeeper
}

resource = input {
    not is_gatekeeper
}

format(msg) = msg {
    not is_gatekeeper
}

format(msg) = {"msg": msg} {
    is_gatekeeper
}

apiVersion = resource.apiVersion
name = resource.metadata.name
kind = resource.kind
labels = resource.metadata.labels
annotations = resource.metadata.annotations

has_field(obj, field) {
    not object.get(obj, field, "N_DEFINED") == "N_DEFINED"
}

missing_field(obj, field) = true {
    obj[field] == ""
}

missing_field(obj, field) = true {
    not has_field(obj, field)
}
