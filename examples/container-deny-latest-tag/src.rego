package container_deny_latest_tag

import data.lib.core
import data.lib.containers

# @title Images must not use the latest tag
#
# Using the latest tag on images can cause unexpected problems in production. By specifing a pinned version
# we can have higher confidence that our applications are immutable and do not change unexpectedly.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
    containers.containers[container]
    has_latest_tag(container)

    msg := core.format(sprintf("%s/%s/%s: Images must not use the latest tag", [core.kind, core.name, container.name]))
}

has_latest_tag(c) {
    endswith(c.image, ":latest")
}

has_latest_tag(c) {
    contains(c.image, ":") == false
}
