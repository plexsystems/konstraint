# Konstraint

[![Go Report Card](https://goreportcard.com/badge/github.com/plexsystems/konstraint)](https://goreportcard.com/report/github.com/plexsystems/konstraint)

![logo](images/logo.png)

Konstraint is a CLI tool to assist with the creation and management of constraints when using [Gatekeeper](https://github.com/open-policy-agent/gatekeeper).

## Why this tool exists

### Automatically copy Rego to the ConstraintTemplate

When writing policies for Gatekeeper, the Rego must be added to [ConstraintTemplates](https://github.com/open-policy-agent/gatekeeper#constraint-templates) in order for Gatekeeper to enforce the policy. This creates a scenario in which the Rego is written in a `.rego` file, and then copied into the ConstraintTemplate. When a change is needed to be made to the Rego, both instances must be updated.

### Automatically update all ConstraintTemplates with library changes

Gatekeeper supports importing _libraries_ into `ConstraintTemplates` with the `libs` field. If a change is required to the imported library, every template must be updated to include this new change.

### Enable writing the same policies for Conftest and Gatekeeper

With Gatekeeper, policies are evaluated in the context of an [AdmissionReview](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#webhook-request-and-response). This means that policies are typically written with a prefix of `input.review.object`.

With [Conftest](https://github.com/open-policy-agent/conftest), policies are written against `yaml` files.

This creates a scenario where the policy needs to be written differently depending upon the context in which the policy is being evaluated in.

`Konstraint` aims to:

- Auto-generate both `ConstraintTemplates` and the Constraints themselves. The `.rego` files are the source of truth and all development should happen in those files.

- Enable the same policy to be used with Gatekeeper `AdmissionReviews` and Conftest `yaml` files. This is accomplished with the _Kubernetes library_.

### Kubernetes library

In the [examples/lib](examples/lib) directory, there is a `kubernetes.rego` file that enables policies to be written for both Conftest and Gatekeeper.

#### Purpose

By first validating the Kubernetes manifests with `Conftest` on a local machine, we are able to catch manifests that would otherwise violate policy without needing to deploy to a cluster running Gatekeeper.

## Installation

```text
GO111MODULE=on go get github.com/plexsystems/konstraint
```

## Usage

### Create command

Create `ConstraintTemplates` and Constraints from `Rego` policies:

```shell
$ konstraint create <dir>
```

This will generate both _templates_ and _constraints_ for the policies found in the directory (and subdirectories), ignoring test files (`*_test.rego`).

#### Create flags

`--ignore` A parameter that accepts `regex` to ignore files and directories.

_Example: konstraint create --ignore combined-policies/_

`--lib` Set the name of the library folder. Defaults to `lib`.

_Example: konstraint create --lib library_

`--exclude-namespace` or `-e` excludes a namespace from the constraint. This flag can be specified more than once. Cannot be used with `--include-namespace`.

_Example: konstraint create -e kube-system -e gatekeeper-system_

`--include-namespace` or `-i` specifies a namespace to apply the constraint to, excluding all others. This flag can be specified more than once. Cannot be used with `--exclude-namespace`. 

_Example: konstraint create -i unique-namespace_

### Doc command

Generate documentation from policies that set `@Kinds` in their comment headers

```shell
$ konstraint doc <dir>
```

This will generate a single `policies.md` file that contains a description of all of the policies found as well as the API groups and Kinds that they enforce.

#### Doc flags

`--output` Set the output directory and filename for the policy documentation.

_Example: konstraint doc --output examples/policies.md_

## How template and constraint naming works

The name of the ConstraintTemplate is derived from the name of the folder that the policy was found in.

For example, a policy found in: `policies/pod-volume-size-limits/src.rego` generates the following in the `policies/pod-volume-size-limits` directory:

- `template.yaml` (defining a ConstraintTemplate)
  - kind: _ConstraintTemplate_
  - name: _podvolumesizelimits_
  - kind (to add to Kubernetes API): _PodVolumeSizeLimits_

- `constraint.yaml` (implementing the above ConstraintTemplate)
  - kind: _PodVolumeSizeLimits_
  - name: _podvolumesizelimits_

_While not technically required, the tool works best with a folder structure similar to how Gatekeeper itself [structures policies and templates](https://github.com/open-policy-agent/gatekeeper/tree/master/library)._

## Experimental

To further promote that the `.rego` file is the source of truth for policy, a form of block comments on each `violation` rule can be added that includes a human readable description of what the policy does. This comment block is also used to set the matchers on the `Constraint` itself.

```rego
# All images deployed to the cluster must not contain a latest tag.
# @Kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
  has_latest_tag

  msg := k8s.format(sprintf("(%s) %s: Images must not use the latest tag", [k8s.kind, k8s.name]))
}
```

The [examples/policies.md](examples/policies.md) file in this repository was generated by running:

```shell
$ konstraint doc --output examples/policies.md
```

At the root of the repository.
