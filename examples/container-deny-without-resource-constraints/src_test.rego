package container_deny_without_resource_constraints

test_input_as_container_missing_resources {
	container := {}

	not container_resources_provided(container)
}

test_input_as_container_with_missing_memory_requests {
	container := {"resources": {"requests": {"cpu": "1"}}}

	not container_resources_provided(container)
}

test_input_as_container_with_missing_limits_constraint {
	container := {"resources": {"requests": {"cpu": "1", "memory": "1"}}}

	not container_resources_provided(container)
}

test_input_as_container_with_all_constraints {
	container := {"resources": {"requests": {"cpu": "1", "memory": "1"}, "limits": {"cpu": "1", "memory": "1"}}}

	container_resources_provided(container)
}
