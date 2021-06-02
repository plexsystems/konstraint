# @title Images must not use the latest tag
#
# Using the latest tag on images can cause unexpected problems in production. By specifying a pinned version
# we can have higher confidence that our applications are immutable and do not change unexpectedly.
#
# The following snippet is an example of how to satisfy this requirement:
#
# ```
# apiVersion: apps/v1
# kind: Deployment
# metadata:
#   name: redis
# spec:
#   template:
#     spec:
#       containers:
#         - name: redis
#           image: redis:6.2
# ```
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
package container_deny_latest_tag

import data.lib.core
import data.lib.pods

policyID := "P2001"

violation[msg] {
    pods.containers[container]
    has_latest_tag(container)

    msg := core.format_with_id(sprintf("%s/%s/%s: Images must not use the latest tag", [core.kind, core.name, container.name]), policyID)
}

has_latest_tag(c) {
    endswith(c.image, ":latest")
}

has_latest_tag(c) {
    contains(c.image, ":") == false
}
