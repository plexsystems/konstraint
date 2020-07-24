package container_latest_tag

test_input_as_image_without_latest_tag {
  input := {
    "kind": "Pod",
    "spec": {
      "containers": [{"image": "image:1.0.0"}]
    }
  }

  not has_latest_tag with input as input
}

test_input_as_image_with_latest_tag {
  input := {
    "kind": "Pod",
    "spec": {
      "containers": [{"image": "image:latest"}]
    }
  }

  has_latest_tag with input as input
}

test_input_as_image_with_no_tag {
  input := {
    "kind": "Pod",
    "spec": {
      "containers": [{"image": "image"}]
    }
  }

  has_latest_tag with input as input
}
