package policy

test_input_as_volume_missing_sizelimit {
  input := {
    "kind": "Pod",
    "spec": {
      "volumes": [{"emptyDir"}]
    }
  }

  volumes_emptydir_size_limit_required with input as input
}

test_input_as_volume_has_size_limit {
  input := {
    "kind": "Pod",
    "spec": {
      "volumes": [{"emptyDir": {"sizeLimit": "256Mi"}}]
    }
  }

  not volumes_emptydir_size_limit_required with input as input
}
