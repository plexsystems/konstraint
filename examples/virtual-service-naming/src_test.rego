package policy

test_input_as_invalid_name {
  input := {
    "kind": "VirtualService",
    "metadata": {
      "name": "virtual-service"
    }
  }

  not virtualservice_name_allowed with input as input
}

test_input_as_valid_name {
  input := {
    "kind": "VirtualService",
    "metadata": {
      "name": "valid-name"
    }
  }

  virtualservice_name_allowed with input as input
}
