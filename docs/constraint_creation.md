# How Constraints are Created

## Policy File Parsing

When using `konstraint create`, Konstraint will only generate templates and constraints for policy files with at least one `violation[]` rule. The `violation` rule is required by Gatekeeper when evaluating policies on a Kubernetes cluster.

When using `konstraint doc`, Konstraint will create documentation for each policy file and assign a severity based on the rule names found in the policy.

The following rule names are organized into their own sections as they have special meaning within the context of Gatekeeper and Conftest:

- `violation`
- `warn`

If a policy file does not contain any of the above rules, the policy is added to the `Other` section.

## Importing Libraries

The Rego for the libraries will be added to the generated `ConstraintTemplate` if and only if the policy imports the library. This helps prevent importing Rego code that will go unused.

## Resource Naming

The name of the templates and constraints are derived from the name of the folder that the policy was found in.

For example, a policy found in: `policies/pod-volume-size-limits/src.rego` generates the following in the `policies/pod-volume-size-limits` directory:

- `template.yaml` (defining a ConstraintTemplate)
  - kind: _ConstraintTemplate_
  - name: _podvolumesizelimits_
  - CRD kind (to add to Kubernetes API): _PodVolumeSizeLimits_

- `constraint.yaml` (implementing the above ConstraintTemplate)
  - kind: _PodVolumeSizeLimits_
  - name: _podvolumesizelimits_

When using the `--output` flag, all templates and constraints will be generated in the path specified in the parameter with the format:

- constraint_PodVolumeSizeLimits.yaml
- template_PodVolumeSizeLimits.yaml

_NOTE: While not technically required, the tool works best with a folder structure similar to how Gatekeeper itself [structures policies and templates](https://github.com/open-policy-agent/gatekeeper-library/tree/master/library)._

## Annotating Policies

To further promote that the `.rego` file is the source of truth for policy, a block comment can be added to each policy file. Konstraint uses the [OPA Metadata Annotations](https://www.openpolicyagent.org/docs/latest/policy-language/#annotations) to achieve this. The OPA metadata annotations are a YAML document in the comments above the package declaration preceded by a line containing the `METADATA` tag. Standard metadata fields are use where possible, but additional Gatekeeper-specific annotations are used under the `custom` metadata key as necessary. The metadata comment block is also what is used when generating documentation via the `doc` command.

This comment block should:

- Include a title that succinctly describes the policy.
- Include a human readable description of what the policy does.
- Set the matchers used when generating the Constraints.

It may also specify the [enforcement action](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/#the-enforcementaction-field) (`deny`, `warn`, or `dryrun`) that Gatekeeper should take when a resource violates the constraint. If no enforcement action is specified, Konstraint defaults to using `deny` to align with Gatekeeper's default action. If the enforcement is set to `dryrun`, the policy will be skipped in the documentation generation.

```rego
# METADATA
# title: Pods must not run with access to the host IPC
# description: >-
#   Pods that are allowed to access the host IPC can read memory of
#   the other containers, breaking that security boundary.
# custom:
#   enforcement: dryrun
package pod_deny_host_ipc

import data.lib.core
import data.lib.pods

violation[msg] {
    pod_has_hostipc

    msg := core.format(sprintf("%s/%s: Pod allows for accessing the host IPC", [core.kind, core.name]))
}

pod_has_hostipc {
    pods.pod.spec.hostIPC
}
```

### Annotating rules for matchers

Any matchers that Gatekeeper [supports](https://open-policy-agent.github.io/gatekeeper/website/docs/howto/#the-match-field) can be added under the `custom.matchers` annotation. These matchers are embedded into the `ConstraintTemplate` resource as-is. The example below will create a `ConstraintTemplate` that only applies to Kubernetes [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) resources in namespaces named `foo`, `bar`, or `baz`.

```rego
# METADATA
# title: Matchers example
# description: Only applies to Deployments in the 'foo', 'bar', and 'baz' namespaces.
# custom:
#   matchers:
#     kinds:
#     - apiGroups:
#       - apps
#       kinds:
#       - Deployment
#     namespaces:
#     - foo
#     - bar
#     - baz
package main

import data.lib.core

violation[{"msg": msg}] {
    msg := sprintf("%v is a Deployment in the foo, bar, or baz namespace", [core.resource])
}
```

### Skipping generation of the Constraint and/or ConstraintTemplate resource

In some scenarios, you may wish for Konstraint to skip the generation of the `Constraint` resource for a policy and manage that externally. To do so, add the `skipConstraint: true` annotation in the custom metadata section.

You can also skip the generation of both the `Constraint` and `ConstraintTemplate` resource with the `skipTemplate: true` annotation
in the custom metadata section.

### Legacy annotations

Previously Konstraint had custom annotation format, such as `@title` or `@kinds`, which is a legacy format and were removed in release v0.39.0.

## Using Input Parameters

Gatekeeper has the ability for a single `ConstraintTemplate` resource to be used by multiple `Constraint`s. One of the reasons for this is that it allows for passing input parameters to the policy so a single policy to avoid duplication. Konstraint supports these input parameters via the `parameters` object in the custom metadata section. **NOTE:** When input parameters are specified, Konstraint skips the generation of the `Constraint` resource unless the `--partial-constraint` flag is set.

The contents of the `parameters` key must be a dictionary (aka map) where the key is the name of the parameter following the [OpenAPI V3 schema](https://swagger.io/specification/). This means each dictionary must, at a minimum, also include a `type` field that indicates what the type of the input is. The example below demonstrates an input that blocks resources that are missing any of the required labels specified in the parameters.

```rego
# METADATA
# title: Required Labels
# description: >-
#  This policy allows you to require certain labels are set on a resource.
# custom:
#   parameters:
#     labels:
#       type: array
#       description: Array of required label keys.
#       items:
#         type: string
package required_labels

import data.lib.core

violation[msg] {
    missing := missing_labels
    count(missing) > 0

    msg := sprintf("%s/%s: Missing required labels: %v", [core.kind, core.name, missing])
}

missing_labels = missing {
    provided := {label | core.labels[label]}
    required := {label | label := input.parameters.labels[_]}
    missing := required - provided
}
```

## Setting constraint metadata.annotations and metadata.labels

You can optionally specify annotations and labels for the generated Constraint. This can be useful if you use Argo CD for deployment (see [here](https://argo-cd.readthedocs.io/en/stable/user-guide/sync-options/#skip-dry-run-for-new-custom-resources-types)).

```rego
# METADATA
# title: Required Labels
# description: >-
#  This policy allows you to require certain labels are set on a resource.
# custom:
#   annotations:
#     "argocd.argoproj.io/sync-options": "SkipDryRunOnMissingResource=true"
...
```
