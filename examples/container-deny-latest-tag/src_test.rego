package container_deny_latest_tag

test_input_as_image_without_latest_tag {
	not has_latest_tag({"name": "test", "image": "image:1.0.0"})
}

test_input_as_image_with_latest_tag {
	has_latest_tag({"name": "test", "image": "image:latest"})
}

test_input_as_image_with_no_tag {
	has_latest_tag({"name": "test", "image": "image"})
}
