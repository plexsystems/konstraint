package lib.core

default is_gatekeeper = false

is_gatekeeper {
  has_field(input, "review")
  has_field(input.review, "object")
}

object = input {
  not is_gatekeeper
}

object = input.review.object {
  is_gatekeeper
}

format(msg) = gatekeeper_format {
  is_gatekeeper
  gatekeeper_format = {"msg": msg}
}

format(msg) = msg {
  not is_gatekeeper
}

name = object.metadata.name

kind = object.kind

api_version = object.apiVersion

has_field(obj, field) {
  obj[field]
}

missing_field(obj, field) = true {
  obj[field] == ""
}

missing_field(obj, field) = true {
  not has_field(obj, field)
}
