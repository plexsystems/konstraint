package container_resource_constraints

test_input_as_container_missing_resources {
  input := {
    "kind": "Pod",
    "spec": {
      "containers": [{}]
    }
  }

  containers_resource_constraints_required with input as input
}

test_input_as_container_with_missing_memory_requests {
  input := {
    "kind": "Pod",
    "spec": {
      "containers": [{"resources": {"requests": {"cpu": "1"}}}]
    }
  }

  containers_resource_constraints_required with input as input
}

test_input_as_container_with_missing_limits_constraint {
  input := {
    "kind": "Pod",
    "spec": {
      "containers": [{"resources": {"requests": {"cpu": "1", "memory": "1"}}}]
    }
  }

  containers_resource_constraints_required with input as input
}

test_input_as_container_with_all_constraints {
  input := {
    "kind": "Pod",
    "spec": {
      "containers": [{"resources": {"requests": {"cpu": "1", "memory": "1"}, "limits": {"cpu": "1", "memory": "1"}}}]
    }
  }

  not containers_resource_constraints_required with input as input
}
