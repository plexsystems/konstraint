package lib.core

test_not_gk {
  input := {
    "kind": "test"
  }

  not is_gatekeeper with input as input
}

test_is_gk {
  input := {
    "review": {
      "object": {
        "kind": "test"
      }
    }
  }

  is_gatekeeper with input as input
}

test_has_field_pos {
  obj := {
    "kind": "test"
  }

  has_field(obj, "kind")
}

test_has_field_neg {
  obj := {
    "kind": "test"
  }
  
  not has_field(obj, "abc")
}
