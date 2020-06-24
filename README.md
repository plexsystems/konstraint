# Konstraint

[![Go Report Card](https://goreportcard.com/badge/github.com/plexsystems/konstraint)](https://goreportcard.com/report/github.com/plexsystems/konstraint)

![logo](images/logo.png)

Konstraint is a CLI tool to assist with the creation and management of constraints when using [Gatekeeper](https://github.com/open-policy-agent/gatekeeper)

**NOTE: THIS TOOL IS CURRENTLY A WORK IN PROGRESS AND SUBJECT TO CHANGE**

## Installation

```text
GO111MODULE=on go get github.com/plexsystems/konstraint
```

## Usage

Create `ConstraintTemplates` and Constraints from `Rego` policies:

`konstraint create <dir>`

This will generate both _templates_ (template.yaml) and _constraints_ (constraint.yaml) for the policies found in the directory (and subdirectories), ignored test files (`*_test.rego`).

### Flags

`--ignore` Ignores all occurances of a given directory by name.
_Example: konstraint create . --ignore combined-policies_

This can be useful if you are also using [Conftest](https://github.com/open-policy-agent/conftest) and have a separate directory for policies intended to be used with the [--combine](https://www.conftest.dev/options/#-combine) flag, and not added to a Kubernetes cluster.

## Template and Constraint Naming

The name of the ConstraintTemplate is derived from the name of the folder that the policy was found in.

For example, a policy found in: `policies/pod-volume-size-limits/src.rego` generates the following in the `policies/pod-volume-size-limits` directory:

- A `ConstraintTemplate` (as `template.yaml`) with the name `podvolumesizelimits` and a `Kind` value in the spec section to `PodVolumeSizeLimits`.

- A _constraint_ of `kind: PodVolumeSizeLimits` and name `podvolumesizelimits` (as `constraint.yaml`)

The tool works best with a folder structure similar to how Gatekeeper itself structures policies and templates. [https://github.com/open-policy-agent/gatekeeper/tree/master/library](https://github.com/open-policy-agent/gatekeeper/tree/master/library)

## Importing Libraries

Importing a library is also supported, a rego library should be placed in the `lib` folder.

`Konstraint` will then add the Rego from the library into the `libs` section of the `ConstraintTemplate`.
