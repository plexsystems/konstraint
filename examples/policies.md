# Policies

* [Images must not use the latest tag](#Images-must-not-use-the-latest-tag)
* [Containers must define resource constraints](#Containers-must-define-resource-constraints)

## Images must not use the latest tag

Using the latest tag on images can cause unexpected problems downloading stuff. By specifing a pinned version
we can have higher confidence that our applications are immutable and do not change unexpectedly.

Resources: apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod

### Rego

```rego
package main

import data.lib.k8s

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
```
_source: [containers-latest-tag](containers-latest-tag)_

## Containers must define resource constraints

Resource constraints on containers ensure that a given workload does not take up more resources than it required
and potentially starve other applications that need to run.

Resources: apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod

### Rego

```rego
package policy

import data.lib.k8s

violation[msg] {
  containers_resource_constraints_required

  msg := k8s.format(sprintf("(%s) %s: Container resource constraints must be specified", [k8s.kind, k8s.name]))
}

containers_resource_constraints_required {
  k8s.is_workload
  not container_resources_provided
}

container_resources_provided {
  k8s.containers[_].resources.requests.cpu
  k8s.containers[_].resources.requests.memory
  k8s.containers[_].resources.limits.cpu
  k8s.containers[_].resources.limits.memory
}
```
_source: [containers-resource-constraints](containers-resource-constraints)_
