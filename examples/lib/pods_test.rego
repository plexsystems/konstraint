package lib.pods

test_input_as_other {
	resource := pod with input as {
		"kind": "Other",
		"spec": {"containers": [{}]},
	}

	not resource
}

test_input_as_pod {
	resource := pod with input as {
		"kind": "Pod",
		"spec": {"containers": [{}]},
	}

	resource.spec.containers
}

test_input_as_deployment {
	resource := pod with input as {
		"kind": "Deployment",
		"spec": {"template": {"spec": {"containers": [{}]}}},
	}

	resource.spec.containers
}

test_input_as_cronjob {
	resource := pod with input as {
		"kind": "CronJob",
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{}]}}}}},
	}

	resource.spec.containers
}

test_containers {
	podcontainers := containers with input as {
		"kind": "Pod",
		"spec": {"containers": [{"name": "container"}]},
	}

	podcontainers[_].name == "container"
}

test_volumes {
	podvolumes := volumes with input as {
		"kind": "Pod",
		"spec": {"volumes": [{"name": "volume"}]},
	}

	podvolumes[_].name == "volume"
}
