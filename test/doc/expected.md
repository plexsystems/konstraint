# Policies

## Violations

* [Images must not use the latest tag](#Images-must-not-use-the-latest-tag)
* [Containers must define resource constraints](#Containers-must-define-resource-constraints)

## Warnings

* [Deprecated Deployment and DaemonSet API](#Deprecated-Deployment-and-DaemonSet-API)

## Images must not use the latest tag

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Using the latest tag on images can cause unexpected problems in production. By specifing a pinned version
we can have higher confidence that our applications are immutable and do not change unexpectedly.

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
_source: [../../examples/containers-latest-tag](../../examples/containers-latest-tag)_

## Containers must define resource constraints

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Resource constraints on containers ensure that a given workload does not take up more resources than it required
and potentially starve other applications that need to run.

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
_source: [../../examples/containers-resource-constraints](../../examples/containers-resource-constraints)_

## Deprecated Deployment and DaemonSet API

**Severity:** warn

**Resources:** apps/DaemonSet apps/Deployment


The `extensions/v1beta1 API` has been deprecated in favor of `apps/v1`. Later versions of Kubernetes
remove this API so to ensure that the Deployment or DaemonSet can be successfully deployed to the cluster,
the version for both of these resources must be `apps/v1`.

### Rego

```rego
package main

import data.lib.k8s

warn[msg] {
  resources := ["DaemonSet", "Deployment"]
  input.apiVersion == "extensions/v1beta1"
  input.kind == resources[_]

  msg := k8s.format(sprintf("%s/%s: API extensions/v1beta1 for %s has been deprecated, use apps/v1 instead.", [input.kind, input.metadata.name, input.kind]))
}

```
_source: [../../examples/warnings](../../examples/warnings)_
