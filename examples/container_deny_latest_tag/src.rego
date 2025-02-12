# METADATA
# title: Images must not use the latest tag
# description: |-
#   Using the latest tag on images can cause unexpected problems in production. By specifying a pinned version
#   we can have higher confidence that our applications are immutable and do not change unexpectedly.
#
#   The following snippet is an example of how to satisfy this requirement:
#
#    ```
#    apiVersion: apps/v1
#    kind: Deployment
#    metadata:
#      name: redis
#    spec:
#      template:
#        spec:
#          containers:
#            - name: redis
#              image: redis:6.2
#   ```
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - ""
#       kinds:
#       - Pod
#     - apiGroups:
#       - apps
#       kinds:
#       - DaemonSet
#       - Deployment
#       - StatefulSet
package container_deny_latest_tag

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P2001"

violation contains msg if {
	some container
	pods.containers[container]
	has_latest_tag(container)

	msg := core.format_with_id(
		sprintf("%s/%s/%s: Images must not use the latest tag", [core.kind, core.name, container.name]),
		policyID,
	)
}

has_latest_tag(c) if {
	endswith(c.image, ":latest")
}

has_latest_tag(c) if {
	contains(c.image, ":") == false
}
