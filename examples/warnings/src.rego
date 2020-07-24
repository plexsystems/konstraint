package main

import data.lib.k8s

# @title Deprecated Deployment and DaemonSet API
#
# The `extensions/v1beta1 API` has been deprecated in favor of `apps/v1`. Later versions of Kubernetes
# remove this API so to ensure that the Deployment or DaemonSet can be successfully deployed to the cluster,
# the version for both of these resources must be `apps/v1`.
# 
# @kinds apps/DaemonSet apps/Deployment
warn[msg] {
  resources := ["DaemonSet", "Deployment"]
  input.apiVersion == "extensions/v1beta1"
  input.kind == resources[_]

  msg := k8s.format(sprintf("%s/%s: API extensions/v1beta1 for %s has been deprecated, use apps/v1 instead.", [input.kind, input.metadata.name, input.kind]))
}
