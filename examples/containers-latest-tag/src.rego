package main

import data.lib.k8s

# @title Images must not use the latest tag
#
# Using the latest tag on images can cause unexpected problems downloading stuff. By specifing a pinned version
# we can have higher confidence that our applications are immutable and do not change unexpectedly.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
  has_latest_tag

  msg := k8s.format(sprintf("(%s) %s: Images must not use the latest tag", [k8s.kind, k8s.name]))
}

has_latest_tag {
  endswith(k8s.container_images[_], ":latest")
}

has_latest_tag {
  contains(k8s.container_images[_], ":") == false
}
