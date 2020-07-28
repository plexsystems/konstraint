# Policies

## Violations

* [Images must not use the latest tag](#images-must-not-use-the-latest-tag)
* [Containers must not run as privileged](#containers-must-not-run-as-privileged)
* [Containers must define resource constraints](#containers-must-define-resource-constraints)

## Warnings

* [Deprecated Deployment and DaemonSet API](#deprecated-deployment-and-daemonset-api)

## Images must not use the latest tag

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Using the latest tag on images can cause unexpected problems in production. By specifing a pinned version
we can have higher confidence that our applications are immutable and do not change unexpectedly.

### Rego

```rego
package container_latest_tag

import data.lib.core
import data.lib.workloads

violation[msg] {
  workloads.containers[container]
  has_latest_tag(container)

  msg := core.format(sprintf("(%s) %s: Images must not use the latest tag", [core.kind, core.name]))
}

has_latest_tag(c) {
  endswith(c.image, ":latest")
}

has_latest_tag(c) {
  contains(c.image, ":") == false
}

```
_source: [../../examples/deny-containers-latest-tag](../../examples/deny-containers-latest-tag)_

## Containers must not run as privileged

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Privileged containers can easily escalate to root privileges on the node. As
such containers running as privileged or with sufficient capabilities granted
to obtain the same effect are not allowed.

### Rego

```rego
package deny_privileged_containers

import data.lib.core
import data.lib.workloads
import data.lib.security


violation[msg] {
  workloads.containers[container]
  is_privileged(container)

  msg = core.format(sprintf("(%s) %s: Containers are not allowed to run as privileged", [core.kind, core.name]))
}

is_privileged(container) {
  container.securityContext.privileged
}

is_privileged(container) {
  security.added_capability(container, "CAP_SYS_ADMIN")
}

```
_source: [../../examples/deny-privileged-containers](../../examples/deny-privileged-containers)_

## Containers must define resource constraints

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Resource constraints on containers ensure that a given workload does not take up more resources than it required
and potentially starve other applications that need to run.

### Rego

```rego
package container_resource_constraints

import data.lib.core
import data.lib.workloads

violation[msg] {
  containers_resource_constraints_required

  msg := core.format(sprintf("(%s) %s: Container resource constraints must be specified", [core.kind, core.name]))
}

containers_resource_constraints_required {
  workloads.is_workload
  not container_resources_provided
}

container_resources_provided {
  workloads.containers[_].resources.requests.cpu
  workloads.containers[_].resources.requests.memory
  workloads.containers[_].resources.limits.cpu
  workloads.containers[_].resources.limits.memory
}

```
_source: [../../examples/require-containers-resource-constraints](../../examples/require-containers-resource-constraints)_

## Deprecated Deployment and DaemonSet API

**Severity:** warn

**Resources:** apps/DaemonSet apps/Deployment


The `extensions/v1beta1 API` has been deprecated in favor of `apps/v1`. Later versions of Kubernetes
remove this API so to ensure that the Deployment or DaemonSet can be successfully deployed to the cluster,
the version for both of these resources must be `apps/v1`.

### Rego

```rego
package warn_deprecated_api_versions

import data.lib.core

warn[msg] {
  resources := ["DaemonSet", "Deployment"]
  core.apiVersion == "extensions/v1beta1"
  core.kind == resources[_]

  msg := core.format(sprintf("API extensions/v1beta1 for %s has been deprecated, use apps/v1 instead.", [core.kind]))
}

```
_source: [../../examples/warn-deprecated-api-versions](../../examples/warn-deprecated-api-versions)_
