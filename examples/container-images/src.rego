package main

import data.lib.k8s

# Container images can not use the latest tag.
# @Kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
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
