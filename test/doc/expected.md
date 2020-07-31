# Policies

## Violations

* [Containers must drop all capabilitites](#containers-must-drop-all-capabilitites)
* [Containers must not allow for privilege escalation](#containers-must-not-allow-for-privilege-escalation)
* [Images must not use the latest tag](#images-must-not-use-the-latest-tag)
* [Containers must not run as privileged](#containers-must-not-run-as-privileged)
* [Containers must define resource constraints](#containers-must-define-resource-constraints)
* [Pods must not have access to the host aliases](#pods-must-not-have-access-to-the-host-aliases)
* [Pods must not run with access to the host IPC](#pods-must-not-run-with-access-to-the-host-ipc)
* [Pods must not run with access to the host networking](#pods-must-not-run-with-access-to-the-host-networking)
* [Pods must not run with access to the host PID namespace](#pods-must-not-run-with-access-to-the-host-pid-namespace)
* [Pods must run as non-root](#pods-must-run-as-non-root)
* [PodSecurityPolicies must require all capabilities are dropped](#podsecuritypolicies-must-require-all-capabilities-are-dropped)
* [PodSecurityPolicies must not allow privileged escalation](#podsecuritypolicies-must-not-allow-privileged-escalation)
* [PodSecurityPolicies must not allow access to the host aliases](#podsecuritypolicies-must-not-allow-access-to-the-host-aliases)
* [PodSecurityPolicies must not allow access to the host IPC](#podsecuritypolicies-must-not-allow-access-to-the-host-ipc)
* [PodSecurityPolicies must not allow access to the host network](#podsecuritypolicies-must-not-allow-access-to-the-host-network)
* [PodSecurityPolicies must not allow access to the host PID namespace](#podsecuritypolicies-must-not-allow-access-to-the-host-pid-namespace)
* [PodSecurityPolicies must require containers to not run as privileged](#podsecuritypolicies-must-require-containers-to-not-run-as-privileged)

## Warnings

* [Deprecated Deployment and DaemonSet API](#deprecated-deployment-and-daemonset-api)
* [Containers should not have a writable root filesystem](#containers-should-not-have-a-writable-root-filesystem)
* [PodSecurityPolicies should require that a read-only root filesystem is set](#podsecuritypolicies-should-require-that-a-read-only-root-filesystem-is-set)

## Containers must drop all capabilitites

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Granting containers privileged capabilities on the node makes it easier
for containers to escalate their privileges. As such, this is not allowed
outside of Kubernetes controller namespaces.

### Rego

```rego
package container_deny_added_caps

import data.lib.core
import data.lib.containers
import data.lib.security

violation[msg] {
    containers.containers[container]
    not security.dropped_capability(container, "all")
    msg = core.format(sprintf("%s/%s/%s: Does not drop all capabilities", [core.kind, core.name, container.name]))
}

```
_source: [../../examples/container-deny-added-caps](../../examples/container-deny-added-caps)_

## Containers must not allow for privilege escalation

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Privileged containers can much more easily obtain root on the node.
As such, they are not allowed.

### Rego

```rego
package container_deny_escalation

import data.lib.core
import data.lib.containers

violation[msg] {
    containers.containers[container]
    allows_escalation(container)
    msg = core.format(sprintf("%s/%s/%s: Allows priviledge escalation", [core.kind, core.name, container.name]))
}

allows_escalation(c) {
    c.securityContext.allowPrivilegeEscalation == true
}

allows_escalation(c) {
    core.missing_field(c.securityContext, "allowPrivilegeEscalation")
}

```
_source: [../../examples/container-deny-escalation](../../examples/container-deny-escalation)_

## Images must not use the latest tag

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Using the latest tag on images can cause unexpected problems in production. By specifing a pinned version
we can have higher confidence that our applications are immutable and do not change unexpectedly.

### Rego

```rego
package container_deny_latest_tag

import data.lib.core
import data.lib.containers

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

```
_source: [../../examples/container-deny-latest-tag](../../examples/container-deny-latest-tag)_

## Containers must not run as privileged

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Privileged containers can easily escalate to root privileges on the node. As
such containers running as privileged or with sufficient capabilities granted
to obtain the same effect are not allowed.

### Rego

```rego
package container_deny_privileged

import data.lib.core
import data.lib.containers
import data.lib.security


violation[msg] {
  containers.containers[container]
  is_privileged(container)

  msg = core.format(sprintf("%s/%s/%s: Containers must not run as privileged", [core.kind, core.name, container.name]))
}

is_privileged(container) {
  container.securityContext.privileged
}

is_privileged(container) {
  security.added_capability(container, "CAP_SYS_ADMIN")
}

```
_source: [../../examples/container-deny-privileged](../../examples/container-deny-privileged)_

## Containers must define resource constraints

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Resource constraints on containers ensure that a given workload does not take up more resources than it required
and potentially starve other applications that need to run.

### Rego

```rego
package container_deny_without_resource_constraints

import data.lib.core
import data.lib.containers

violation[msg] {
  containers.containers[container]
  not container_resources_provided(container)

  msg := core.format(sprintf("%s/%s/%s: Container resource constraints must be specified", [core.kind, core.name, container.name]))
}

container_resources_provided(container) {
  container.resources.requests.cpu
  container.resources.requests.memory
  container.resources.limits.cpu
  container.resources.limits.memory
}

```
_source: [../../examples/container-deny-without-resource-constraints](../../examples/container-deny-without-resource-constraints)_

## Pods must not have access to the host aliases

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Pods that can change aliases in the host's /etc/hosts file can
redirect traffic to malicious servers.

### Rego

```rego
package pod_deny_host_alias

import data.lib.core
import data.lib.pods

violation[msg] {
    pods.pods[pod]
    pod.spec.hostAliases
    msg = core.format(sprintf("%s/%s/%s: Pod allows for managing host aliases", [core.kind, core.name, pod.metadata.name]))
}

```
_source: [../../examples/pod-deny-host-alias](../../examples/pod-deny-host-alias)_

## Pods must not run with access to the host IPC

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Pods that are allowed to access the host IPC can read memory of
the other containers, breaking that security boundary.

### Rego

```rego
package pod_deny_host_ipc

import data.lib.core
import data.lib.pods

violation[msg] {
    pods.pods[pod]
    pod.spec.hostIPC
    msg = core.format(sprintf("%s/%s/%s: Pod allows for accessing the host IPC", [core.kind, core.name, pod.metadata.name]))
}

```
_source: [../../examples/pod-deny-host-ipc](../../examples/pod-deny-host-ipc)_

## Pods must not run with access to the host networking

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Pods that can access the host's network interfaces can potentially
access and tamper with traffic the pod should not have access to.

### Rego

```rego
package pod_deny_host_network

import data.lib.core
import data.lib.pods

violation[msg] {
    pods.pods[pod]
    pod.spec.hostNetwork
    msg = core.format(sprintf("%s/%s/%s: Pod allows for accessing the host network", [core.kind, core.name, pod.metadata.name]))
}

```
_source: [../../examples/pod-deny-host-network](../../examples/pod-deny-host-network)_

## Pods must not run with access to the host PID namespace

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Pods that can acess the host's process tree can view and attempt to
modify processes outside of their namespace, breaking that security
boundary.

### Rego

```rego
package pod_deny_host_pid

import data.lib.core
import data.lib.pods

violation[msg] {
    pods.pods[pod]
    pod.spec.hostPID
    msg = core.format(sprintf("%s/%s/%s: Pod allows for accessing the host PID namespace", [core.kind, core.name, pod.metadata.name]))
}

```
_source: [../../examples/pod-deny-host-pid](../../examples/pod-deny-host-pid)_

## Pods must run as non-root

**Severity:** violation

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


Pods running as root (uid of 0) can much more easily escalate privileges
to root on the node. As such, they are not allowed.

### Rego

```rego
package pod_deny_without_runasnonroot

import data.lib.pods
import data.lib.core

violation[msg] {
    pods.pods[pod]
    not pod.spec.securityContext.runAsNonRoot
    msg = core.format(sprintf("%s/%s/%s: Pod allows running as root", [core.kind, core.name, pod.metadata.name]))
}

```
_source: [../../examples/pod-deny-without-runasnonroot](../../examples/pod-deny-without-runasnonroot)_

## PodSecurityPolicies must require all capabilities are dropped

**Severity:** violation

**Resources:** policy/PodSecurityPolicy


Allowing containers privileged capabilities on the node makes it easier
for containers to escalate their privileges. As such, this is not allowed
outside of Kubernetes controller namespaces.

### Rego

```rego
package psp_deny_added_caps

import data.lib.core
import data.lib.psps
import data.lib.security

violation[msg] {
    psps.psps[psp]
    not security.dropped_capability(psp, "all")
    msg = core.format(sprintf("%s/%s: Does not require droping all capabilities", [core.kind, core.name]))
}

```
_source: [../../examples/psp-deny-added-caps](../../examples/psp-deny-added-caps)_

## PodSecurityPolicies must not allow privileged escalation

**Severity:** violation

**Resources:** policy/PodSecurityPolicy


Allowing privileged containers can much more easily obtain root on the node.
As such, they are not allowed.

### Rego

```rego
package psp_deny_escalation

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    allows_escalation(psp)
    msg = core.format(sprintf("%s/%s: Allows priviledge escalation", [core.kind, core.name]))
}

allows_escalation(p) {
    p.spec.allowPrivilegeEscalation == true
}

allows_escalation(p) {
    core.missing_field(p.spec, "allowPrivilegeEscalation")
}

```
_source: [../../examples/psp-deny-escalation](../../examples/psp-deny-escalation)_

## PodSecurityPolicies must not allow access to the host aliases

**Severity:** violation

**Resources:** policy/PodSecurityPolicy


Allowing pods to can change aliases in the host's /etc/hosts file can
redirect traffic to malicious servers.

### Rego

```rego
package psp_deny_host_alias

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.hostAliases
    msg = core.format(sprintf("%s/%s: Allows for managing host aliases", [core.kind, core.name]))
}

```
_source: [../../examples/psp-deny-host-alias](../../examples/psp-deny-host-alias)_

## PodSecurityPolicies must not allow access to the host IPC

**Severity:** violation

**Resources:** policy/PodSecurityPolicy


Allowing pods to to access the host IPC can read memory of
the other containers, breaking that security boundary.

### Rego

```rego
package psp_deny_host_ipc

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.hostIPC
    msg = core.format(sprintf("%s/%s: Allows for sharing the host IPC namespace", [core.kind, core.name]))
}

```
_source: [../../examples/psp-deny-host-ipc](../../examples/psp-deny-host-ipc)_

## PodSecurityPolicies must not allow access to the host network

**Severity:** violation

**Resources:** policy/PodSecurityPolicy


Allowing pods to acess the host's process tree can view and attempt to
modify processes outside of their namespace, breaking that security
boundary.

### Rego

```rego
package psp_deny_host_network

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.hostNetwork
    msg = core.format(sprintf("%s/%s: Allows for accessing the host network", [core.kind, core.name]))
}

```
_source: [../../examples/psp-deny-host-network](../../examples/psp-deny-host-network)_

## PodSecurityPolicies must not allow access to the host PID namespace

**Severity:** violation

**Resources:** policy/PodSecurityPolicy


Allowing pods to acess the host's process tree can view and attempt to
modify processes outside of their namespace, breaking that security
boundary.

### Rego

```rego
package psp_deny_host_pid

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.hostPID
    msg = core.format(sprintf("%s/%s: Allows for sharing the host PID namespace", [core.kind, core.name]))
}

```
_source: [../../examples/psp-deny-host-pid](../../examples/psp-deny-host-pid)_

## PodSecurityPolicies must require containers to not run as privileged

**Severity:** violation

**Resources:** policy/PodSecurityPolicy


Allowing privileged containers can much more easily obtain root on the node.
As such, they are not allowed.

### Rego

```rego
package psp_deny_privileged

import data.lib.core
import data.lib.psps

violation[msg] {
    psps.psps[psp]
    psp.spec.privileged
    msg = core.format(sprintf("%s/%s: Allows for privileged workloads", [core.kind, core.name]))
}

```
_source: [../../examples/psp-deny-privileged](../../examples/psp-deny-privileged)_

## Deprecated Deployment and DaemonSet API

**Severity:** warn

**Resources:** apps/DaemonSet apps/Deployment


The `extensions/v1beta1 API` has been deprecated in favor of `apps/v1`. Later versions of Kubernetes
remove this API so to ensure that the Deployment or DaemonSet can be successfully deployed to the cluster,
the version for both of these resources must be `apps/v1`.

### Rego

```rego
package any_warn_deprecated_api_versions

import data.lib.core

warn[msg] {
  resources := ["DaemonSet", "Deployment"]
  core.apiVersion == "extensions/v1beta1"
  core.kind == resources[_]

  msg := core.format(sprintf("API extensions/v1beta1 for %s has been deprecated, use apps/v1 instead.", [core.kind]))
}

```
_source: [../../examples/any-warn-deprecated-api-versions](../../examples/any-warn-deprecated-api-versions)_

## Containers should not have a writable root filesystem

**Severity:** warn

**Resources:** apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod


In order to prevent persistence in the case of a compromise, it is
important to make the root filesystem read-only.

### Rego

```rego
package container_warn_no_ro_fs

import data.lib.containers
import data.lib.core

warn[msg] {
    containers.containers[container]
    no_read_only_filesystem(container)
    msg = core.format(sprintf("%s/%s/%s: Is not using a read only root filesystem", [core.kind, core.name, container.name]))
}

no_read_only_filesystem(container) {
    core.has_field(container.securityContext, "readOnlyRootFilesystem")
    not container.securityContext.readOnlyRootFilesystem
}

no_read_only_filesystem(container) {
    core.missing_field(container.securityContext, "readOnlyRootFilesystem")
}

```
_source: [../../examples/container-warn-no-ro-fs](../../examples/container-warn-no-ro-fs)_

## PodSecurityPolicies should require that a read-only root filesystem is set

**Severity:** warn

**Resources:** policy/PodSecurityPolicy


Allowping pods to access the host's network interfaces can potentially
access and tamper with traffic the pod should not have access to.

### Rego

```rego
package psp_warn_no_ro_fs

import data.lib.core
import data.lib.psps

warn[msg] {
    psps.psps[psp]
    no_read_only_filesystem(psp)
    msg = core.format(sprintf("%s/%s: Allows for a writeable root filesystem", [core.kind, core.name]))
}

no_read_only_filesystem(psp) {
    core.missing_field(psp.spec, "readOnlyRootFilesystem")
}

no_read_only_filesystem(psp) {
    not psp.spec.readOnlyRootFilesystem
}

```
_source: [../../examples/psp-warn-no-ro-fs](../../examples/psp-warn-no-ro-fs)_
