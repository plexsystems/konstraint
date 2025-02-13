# Policies

## Violations

* [P0002: Required Labels](#p0002-required-labels)
* [P1001: Containers must drop all capabilities](#p1001-containers-must-drop-all-capabilities)
* [P1002: Containers must not allow for privilege escalation](#p1002-containers-must-not-allow-for-privilege-escalation)
* [P1003: Containers must not run as privileged](#p1003-containers-must-not-run-as-privileged)
* [P1004: Pods must not have access to the host aliases](#p1004-pods-must-not-have-access-to-the-host-aliases)
* [P1005: Pods must not run with access to the host IPC](#p1005-pods-must-not-run-with-access-to-the-host-ipc)
* [P1006: Pods must not run with access to the host networking](#p1006-pods-must-not-run-with-access-to-the-host-networking)
* [P1007: Pods must not run with access to the host PID namespace](#p1007-pods-must-not-run-with-access-to-the-host-pid-namespace)
* [P1008: Pods must run as non-root](#p1008-pods-must-run-as-non-root)
* [P1009: PodSecurityPolicies must require all capabilities are dropped](#p1009-podsecuritypolicies-must-require-all-capabilities-are-dropped)
* [P1010: PodSecurityPolicies must not allow privileged escalation](#p1010-podsecuritypolicies-must-not-allow-privileged-escalation)
* [P1011: PodSecurityPolicies must not allow access to the host aliases](#p1011-podsecuritypolicies-must-not-allow-access-to-the-host-aliases)
* [P1012: PodSecurityPolicies must not allow access to the host IPC](#p1012-podsecuritypolicies-must-not-allow-access-to-the-host-ipc)
* [P1013: PodSecurityPolicies must not allow access to the host network](#p1013-podsecuritypolicies-must-not-allow-access-to-the-host-network)
* [P1014: PodSecurityPolicies must not allow access to the host PID namespace](#p1014-podsecuritypolicies-must-not-allow-access-to-the-host-pid-namespace)
* [P1015: PodSecurityPolicies must require containers to not run as privileged](#p1015-podsecuritypolicies-must-require-containers-to-not-run-as-privileged)
* [P2001: Images must not use the latest tag](#p2001-images-must-not-use-the-latest-tag)
* [P2002: Containers must define resource constraints](#p2002-containers-must-define-resource-constraints)
* [P2005: Roles must not allow use of privileged PodSecurityPolicies](#p2005-roles-must-not-allow-use-of-privileged-podsecuritypolicies)
* [P2006: Tenants' containers must not run as privileged](#p2006-tenants'-containers-must-not-run-as-privileged)

## Warnings

* [P0001: Deprecated Deployment and DaemonSet API](#p0001-deprecated-deployment-and-daemonset-api)
* [P2003: Containers should not have a writable root filesystem](#p2003-containers-should-not-have-a-writable-root-filesystem)
* [P2004: PodSecurityPolicies should require that a read-only root filesystem is set](#p2004-podsecuritypolicies-should-require-that-a-read-only-root-filesystem-is-set)

## P0002: Required Labels

**Severity:** Violation

**Resources:**

- Any Resource

**Parameters:**

* labels: array of string
  Array of required label keys.

This policy allows you to require certain labels are set on a resource. Adapted from https://github.com/open-policy-agent/gatekeeper/blob/master/example/templates/k8srequiredlabels_template.yaml

### Rego

```rego
package required_labels

import data.lib.core
import future.keywords.contains
import future.keywords.if

policyID := "P0002"

violation contains msg if {
  count(missing_labels) > 0

  msg := core.format_with_id(
    sprintf("%s/%s: Missing required labels: %v", [core.kind, core.name, missing_labels]),
    policyID,
  )
}

missing_labels := missing if {
  provided := object.keys(core.labels)
  required := {label | label := input.parameters.labels[_]}
  missing := required - provided
}
```

_source: [required_labels](required_labels)_

## P1001: Containers must drop all capabilities

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Granting containers privileged capabilities on the node makes it easier
for containers to escalate their privileges. As such, this is not allowed
outside of Kubernetes controller namespaces.

### Rego

```rego
package container_deny_added_caps

import data.lib.core
import data.lib.pods
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P1001"

violation contains msg if {
  some container
  pods.containers[container]
  not container_dropped_all_capabilities(container)

  msg := core.format_with_id(
    sprintf("%s/%s/%s: Does not drop all capabilities", [core.kind, core.name, container.name]),
    policyID,
  )
}

container_dropped_all_capabilities(container) if {
  security.dropped_capability(container, "all")
}
```

_source: [container_deny_added_caps](container_deny_added_caps)_

## P1002: Containers must not allow for privilege escalation

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Privileged containers can much more easily obtain root on the node.
As such, they are not allowed.

### Rego

```rego
package container_deny_escalation

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P1002"

violation contains msg if {
  some container
  pods.containers[container]
  container_allows_escalation(container)

  msg := core.format_with_id(sprintf("%s/%s: Allows privilege escalation", [core.kind, core.name]), policyID)
}

container_allows_escalation(c) if {
  c.securityContext.allowPrivilegeEscalation == true
}

container_allows_escalation(c) if {
  core.missing_field(c, "securityContext")
}

container_allows_escalation(c) if {
  core.missing_field(c.securityContext, "allowPrivilegeEscalation")
}
```

_source: [container_deny_escalation](container_deny_escalation)_

## P1003: Containers must not run as privileged

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Privileged containers can easily escalate to root privileges on the node. As
such containers running as privileged or with sufficient capabilities granted
to obtain the same effect are not allowed.

### Rego

```rego
package container_deny_privileged

import data.lib.core
import data.lib.pods
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P1003"

violation contains msg if {
  some container
  pods.containers[container]
  container_is_privileged(container)

  msg := core.format_with_id(
    sprintf("%s/%s/%s: Containers must not run as privileged", [core.kind, core.name, container.name]),
    policyID,
  )
}

container_is_privileged(container) if {
  container.securityContext.privileged
}

container_is_privileged(container) if {
  security.added_capability(container, "CAP_SYS_ADMIN")
}
```

_source: [container_deny_privileged](container_deny_privileged)_

## P1004: Pods must not have access to the host aliases

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Pods that can change aliases in the host's /etc/hosts file can redirect traffic to malicious servers.

### Rego

```rego
package pod_deny_host_alias

import future.keywords.contains
import future.keywords.if

import data.lib.core.format_with_id
import data.lib.core.kind
import data.lib.core.name
import data.lib.pods

policyID := "P1004"

violation contains msg if {
  pod_host_alias

  msg := format_with_id(sprintf("%s/%s: Pod has hostAliases defined", [kind, name]), policyID)
}

pod_host_alias if {
  pods.pod.spec.hostAliases
}
```

_source: [pod_deny_host_alias](pod_deny_host_alias)_

## P1005: Pods must not run with access to the host IPC

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Pods that are allowed to access the host IPC can read memory of
the other containers, breaking that security boundary.

### Rego

```rego
package pod_deny_host_ipc

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P1005"

violation contains msg if {
  pod_has_hostipc

  msg := core.format_with_id(sprintf("%s/%s: Pod allows for accessing the host IPC", [core.kind, core.name]), policyID)
}

pod_has_hostipc if {
  pods.pod.spec.hostIPC
}
```

_source: [pod_deny_host_ipc](pod_deny_host_ipc)_

## P1006: Pods must not run with access to the host networking

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Pods that can access the host's network interfaces can potentially
access and tamper with traffic the pod should not have access to.

### Rego

```rego
package pod_deny_host_network

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P1006"

violation contains msg if {
  pod_has_hostnetwork

  msg := core.format_with_id(
    sprintf("%s/%s: Pod allows for accessing the host network", [core.kind, core.name]),
    policyID,
  )
}

pod_has_hostnetwork if {
  pods.pod.spec.hostNetwork
}
```

_source: [pod_deny_host_network](pod_deny_host_network)_

## P1007: Pods must not run with access to the host PID namespace

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Pods that can access the host's process tree can view and attempt to
modify processes outside of their namespace, breaking that security
boundary.

### Rego

```rego
package pod_deny_host_pid

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P1007"

violation contains msg if {
  pod_has_hostpid

  msg := core.format_with_id(
    sprintf("%s/%s: Pod allows for accessing the host PID namespace", [core.kind, core.name]),
    policyID,
  )
}

pod_has_hostpid if {
  pods.pod.spec.hostPID
}
```

_source: [pod_deny_host_pid](pod_deny_host_pid)_

## P1008: Pods must run as non-root

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Pods running as root (uid of 0) can much more easily escalate privileges
to root on the node. As such, they are not allowed.

### Rego

```rego
package pod_deny_without_runasnonroot

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P1008"

violation contains msg if {
  pods.pod
  not pod_runasnonroot

  msg := core.format_with_id(sprintf("%s/%s: Pod allows running as root", [core.kind, core.name]), policyID)
}

pod_runasnonroot if {
  pods.pod.spec.securityContext.runAsNonRoot
}
```

_source: [pod_deny_without_runasnonroot](pod_deny_without_runasnonroot)_

## P1009: PodSecurityPolicies must require all capabilities are dropped

**Severity:** Violation

**Resources:**

- policy/PodSecurityPolicy

Allowing containers privileged capabilities on the node makes it easier
for containers to escalate their privileges. As such, this is not allowed
outside of Kubernetes controller namespaces.

### Rego

```rego
package psp_deny_added_caps

import data.lib.core
import data.lib.psps
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P1009"

violation contains msg if {
  not psp_dropped_all_capabilities

  msg := core.format_with_id(
    sprintf("%s/%s: Does not require droping all capabilities", [core.kind, core.name]),
    policyID,
  )
}

psp_dropped_all_capabilities if {
  some psp
  psps.psps[psp]
  security.dropped_capability(psp, "all")
}
```

_source: [psp_deny_added_caps](psp_deny_added_caps)_

## P1010: PodSecurityPolicies must not allow privileged escalation

**Severity:** Violation

**Resources:**

- policy/PodSecurityPolicy

Allowing privileged containers can much more easily obtain root on the node.
As such, they are not allowed.

### Rego

```rego
package psp_deny_escalation

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1010"

violation contains msg if {
  some psp
  psps.psps[psp]
  allows_escalation(psp)

  msg := core.format_with_id(sprintf("%s/%s: Allows privilege escalation", [core.kind, core.name]), policyID)
}

allows_escalation(p) if {
  p.spec.allowPrivilegeEscalation == true
}

allows_escalation(p) if {
  core.missing_field(p.spec, "allowPrivilegeEscalation")
}
```

_source: [psp_deny_escalation](psp_deny_escalation)_

## P1011: PodSecurityPolicies must not allow access to the host aliases

**Severity:** Violation

**Resources:**

- policy/PodSecurityPolicy

Allowing pods to can change aliases in the host's /etc/hosts file can
redirect traffic to malicious servers.

### Rego

```rego
package psp_deny_host_alias

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1011"

violation contains msg if {
  psp_allows_hostaliases

  msg := core.format_with_id(sprintf("%s/%s: Allows for managing host aliases", [core.kind, core.name]), policyID)
}

psp_allows_hostaliases if {
  psps.psps[_].spec.hostAliases
}
```

_source: [psp_deny_host_alias](psp_deny_host_alias)_

## P1012: PodSecurityPolicies must not allow access to the host IPC

**Severity:** Violation

**Resources:**

- policy/PodSecurityPolicy

Allowing pods to access the host IPC can read memory of
the other containers, breaking that security boundary.

### Rego

```rego
package psp_deny_host_ipc

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1012"

violation contains msg if {
  psp_allows_hostipc

  msg := core.format_with_id(
    sprintf("%s/%s: Allows for sharing the host IPC namespace", [core.kind, core.name]),
    policyID,
  )
}

psp_allows_hostipc if {
  psps.psps[_].spec.hostIPC
}
```

_source: [psp_deny_host_ipc](psp_deny_host_ipc)_

## P1013: PodSecurityPolicies must not allow access to the host network

**Severity:** Violation

**Resources:**

- policy/PodSecurityPolicy

Allowing pods to access the host's process tree can view and attempt to
modify processes outside of their namespace, breaking that security
boundary.

### Rego

```rego
package psp_deny_host_network

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1013"

violation contains msg if {
  psp_allows_hostnetwork

  msg := core.format_with_id(sprintf("%s/%s: Allows for accessing the host network", [core.kind, core.name]), policyID)
}

psp_allows_hostnetwork if {
  psps.psps[_].spec.hostNetwork
}
```

_source: [psp_deny_host_network](psp_deny_host_network)_

## P1014: PodSecurityPolicies must not allow access to the host PID namespace

**Severity:** Violation

**Resources:**

- policy/PodSecurityPolicy

Allowing pods to access the host's process tree can view and attempt to
modify processes outside of their namespace, breaking that security
boundary.

### Rego

```rego
package psp_deny_host_pid

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1014"

violation contains msg if {
  psp_allows_hostpid

  msg = core.format_with_id(
    sprintf("%s/%s: Allows for sharing the host PID namespace", [core.kind, core.name]),
    policyID,
  )
}

psp_allows_hostpid if {
  psps.psps[_].spec.hostPID
}
```

_source: [psp_deny_host_pid](psp_deny_host_pid)_

## P1015: PodSecurityPolicies must require containers to not run as privileged

**Severity:** Violation

**Resources:**

- policy/PodSecurityPolicy

Allowing privileged containers can much more easily obtain root on the node.
As such, they are not allowed.

### Rego

```rego
package psp_deny_privileged

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P1015"

violation contains msg if {
  psp_allows_privileged

  msg := core.format_with_id(sprintf("%s/%s: Allows for privileged workloads", [core.kind, core.name]), policyID)
}

psp_allows_privileged if {
  psps.psps[_].spec.privileged
}
```

_source: [psp_deny_privileged](psp_deny_privileged)_

## P2001: Images must not use the latest tag

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Using the latest tag on images can cause unexpected problems in production. By specifying a pinned version
we can have higher confidence that our applications are immutable and do not change unexpectedly.

The following snippet is an example of how to satisfy this requirement:

 ```
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: redis
 spec:
   template:
     spec:
       containers:
         - name: redis
           image: redis:6.2
```

### Rego

```rego
package container_deny_latest_tag

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P2001"

violation contains msg if {
  some container
  pods.containers[container]
  has_latest_tag(container)

  msg := core.format_with_id(
    sprintf("%s/%s/%s: Images must not use the latest tag", [core.kind, core.name, container.name]),
    policyID,
  )
}

has_latest_tag(c) if {
  endswith(c.image, ":latest")
}

has_latest_tag(c) if {
  contains(c.image, ":") == false
}
```

_source: [container_deny_latest_tag](container_deny_latest_tag)_

## P2002: Containers must define resource constraints

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

Resource constraints on containers ensure that a given workload does not take up more resources than it requires
and potentially starve other applications that need to run.

### Rego

```rego
package container_deny_without_resource_constraints

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P2002"

violation contains msg if {
  some container
  pods.containers[container]
  not container_resources_provided(container)

  msg := core.format_with_id(
    sprintf("%s/%s/%s: Container resource constraints must be specified", [core.kind, core.name, container.name]),
    policyID,
  )
}

container_resources_provided(container) if {
  container.resources.requests.cpu
  container.resources.requests.memory
  container.resources.limits.cpu
  container.resources.limits.memory
}
```

_source: [container_deny_without_resource_constraints](container_deny_without_resource_constraints)_

## P2005: Roles must not allow use of privileged PodSecurityPolicies

**Severity:** Violation

**Resources:**

- rbac.authorization.k8s.io/Role

Workloads not running in the exempted namespaces must not use PodSecurityPolicies with privileged permissions.

### Rego

```rego
package role_deny_use_privileged_psps

import data.lib.core
import data.lib.rbac
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P2005"

violation contains msg if {
  role_uses_privileged_psp

  msg := core.format_with_id(
    sprintf("%s/%s: Allows using PodSecurityPolicies with privileged permissions", [core.kind, core.name]),
    policyID,
  )
}

role_uses_privileged_psp if {
  rule := core.resource.rules[_]
  rbac.rule_has_resource_type(rule, "podsecuritypolicies")
  rbac.rule_has_verb(rule, "use")
  rbac.rule_has_resource_name(rule, privileged_psps[_].metadata.name)
}

privileged_psps contains psp if {
  psp := data.inventory.cluster["policy/v1beta1"].PodSecurityPolicy[_]
  psp_is_privileged(psp)
}

psp_is_privileged(psp) if {
  psp.spec.privileged
}

psp_is_privileged(psp) if {
  security.added_capability(psp, "SYS_ADMIN")
}
```

_source: [role_deny_use_privileged_psps](role_deny_use_privileged_psps)_

## P2006: Tenants' containers must not run as privileged

**Severity:** Violation

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

**MatchLabels:** is-tenant=true

Privileged containers can easily escalate to root privileges on the node. As
such containers running as privileged or with sufficient capabilities granted
to obtain the same effect are not allowed if they are labeled as tenant.
To take advantage of this policy, it must be combined with another policy
that enforces the 'is-tenant' label.

### Rego

```rego
package container_deny_privileged_if_tenant

import data.lib.core
import data.lib.pods
import data.lib.security
import future.keywords.contains
import future.keywords.if

policyID := "P2006"

violation contains msg if {
  some container
  pods.containers[container]
  container_is_privileged(container)

  msg = core.format_with_id(
    sprintf("%s/%s/%s: Tenants' containers must not run as privileged", [core.kind, core.name, container.name]),
    policyID,
  )
}

container_is_privileged(container) if {
  container.securityContext.privileged
}

container_is_privileged(container) if {
  security.added_capability(container, "CAP_SYS_ADMIN")
}
```

_source: [container_deny_privileged_if_tenant](container_deny_privileged_if_tenant)_

## P0001: Deprecated Deployment and DaemonSet API

**Severity:** Warning

**Resources:**

- apps/DaemonSet
- apps/Deployment

The `extensions/v1beta1 API` has been deprecated in favor of `apps/v1`. Later versions of Kubernetes
remove this API so to ensure that the Deployment or DaemonSet can be successfully deployed to the cluster,
the version for both of these resources must be `apps/v1`.

### Rego

```rego
package any_warn_deprecated_api_versions

import data.lib.core
import future.keywords.contains
import future.keywords.if
import future.keywords.in

policyID := "P0001"

warn contains msg if {
  core.apiVersion == "extensions/v1beta1"
  resources := ["DaemonSet", "Deployment"]
  core.kind in resources

  msg := core.format_with_id(
    sprintf("API extensions/v1beta1 for %s has been deprecated, use apps/v1 instead.", [core.kind]),
    policyID,
  )
}
```

_source: [any_warn_deprecated_api_versions](any_warn_deprecated_api_versions)_

## P2003: Containers should not have a writable root filesystem

**Severity:** Warning

**Resources:**

- core/Pod
- apps/DaemonSet
- apps/Deployment
- apps/StatefulSet

In order to prevent persistence in the case of a compromise, it is
important to make the root filesystem read-only.

### Rego

```rego
package container_warn_no_ro_fs

import data.lib.core
import data.lib.pods
import future.keywords.contains
import future.keywords.if

policyID := "P2003"

warn contains msg if {
  some container
  pods.containers[container]
  no_read_only_filesystem(container)

  msg := core.format_with_id(
    sprintf("%s/%s/%s: Is not using a read only root filesystem", [core.kind, core.name, container.name]),
    policyID,
  )
}

no_read_only_filesystem(container) if {
  core.has_field(container.securityContext, "readOnlyRootFilesystem")
  not container.securityContext.readOnlyRootFilesystem
}

no_read_only_filesystem(container) if {
  core.missing_field(container.securityContext, "readOnlyRootFilesystem")
}
```

_source: [container_warn_no_ro_fs](container_warn_no_ro_fs)_

## P2004: PodSecurityPolicies should require that a read-only root filesystem is set

**Severity:** Warning

**Resources:**

- policy/PodSecurityPolicy

Allowing pods to access the host's network interfaces can potentially
access and tamper with traffic the pod should not have access to.

### Rego

```rego
package psp_warn_no_ro_fs

import data.lib.core
import data.lib.psps
import future.keywords.contains
import future.keywords.if

policyID := "P2004"

warn contains msg if {
  some psp
  psps.psps[psp]
  no_read_only_filesystem(psp)

  msg := core.format_with_id(sprintf("%s/%s: Allows for a writeable root filesystem", [core.kind, core.name]), policyID)
}

no_read_only_filesystem(psp) if {
  core.missing_field(psp.spec, "readOnlyRootFilesystem")
}

no_read_only_filesystem(psp) if {
  not psp.spec.readOnlyRootFilesystem
}
```

_source: [psp_warn_no_ro_fs](psp_warn_no_ro_fs)_

