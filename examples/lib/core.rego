package lib.core

default is_gatekeeper = false

is_gatekeeper {
  has_field(input, "review")
  has_field(input.review, "object")
}

resource = input {
  not is_gatekeeper
}

resource = input.review.object {
  is_gatekeeper
}

apiVersion = resource.apiVersion
kind = resource.kind
name = resource.metadata.name
labels = resource.metadata.labels

format(msg) = gatekeeper_format {
  is_gatekeeper
  gatekeeper_format = {"msg": msg}
}

format(msg) = msg {
  not is_gatekeeper
}

has_field(obj, field) {
  obj[field]
}

missing_field(obj, field) = true {
  obj[field] == ""
}

missing_field(obj, field) = true {
  not has_field(obj, field)
}
