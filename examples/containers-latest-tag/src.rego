package container_latest_tag

import data.lib.core
import data.lib.workloads

# @title Images must not use the latest tag
#
# Using the latest tag on images can cause unexpected problems in production. By specifing a pinned version
# we can have higher confidence that our applications are immutable and do not change unexpectedly.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
  has_latest_tag

  msg := core.format(sprintf("(%s) %s: Images must not use the latest tag", [core.kind, core.name]))
}

has_latest_tag {
  endswith(workloads.container_images[_], ":latest")
}

has_latest_tag {
  contains(workloads.container_images[_], ":") == false
}
