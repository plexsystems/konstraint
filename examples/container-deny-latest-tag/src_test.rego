package container_deny_latest_tag

test_input_as_image_without_latest_tag {
  input := {
    "kind": "Pod",
    "metadata": {"name": "test"},
    "spec": {
      "containers": [{"image": "image:1.0.0"}]
    }
  }

  violations := violation with input as input
  count(violations) == 0
}

test_input_as_image_with_latest_tag {
  input := {
    "kind": "Pod",
    "metadata": {"name": "test"},
    "spec": {
      "containers": [{"image": "image:latest"}]
    }
  }

  violations := violation with input as input
  count(violations) == 1
}

test_input_as_image_with_no_tag {
  input := {
    "kind": "Pod",
    "metadata": {"name": "test"},
    "spec": {
      "containers": [{"image": "image"}]
    }
  }

  violations := violation with input as input
  count(violations) == 1
}
