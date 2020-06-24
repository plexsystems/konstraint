# Konstraint

[![Go Report Card](https://goreportcard.com/badge/github.com/plexsystems/konstraint)](https://goreportcard.com/report/github.com/plexsystems/konstraint)

![logo](images/logo.png)

Konstraint is a CLI tool to assist with the creation and management of constraints when using [Gatekeeper](https://github.com/open-policy-agent/gatekeeper)

**NOTE: THIS TOOL IS CURRENTLY A WORK IN PROGRESS AND SUBJECT TO CHANGE**

## Installation

```
GO111MODULE=on go get github.com/plexsystems/konstraint
```

## Usage

To create a `ConstraintTemplate` from a `Rego` policy, you can use the `create` command:

`konstraint create <dir>`

This will generate both _templates_ and _constraints_ for the policies found in the directory.

## Template and Constraint Naming

The name of the ConstraintTemplate is derived from the name of the folder that the policy was found in.

For example, a policy found in: `policies/pod-volume-size-limits/src.rego`

Would generate a `ConstraintTemplate` (as `template.yaml`) with the name `podvolumesizelimits` and a _constraint_ with the name `PodVolumeSizeLimits` (as `constraint.yaml`) in the same directory as the policy.

The tool works best with a folder structure similar to how Gatekeeper itself structures policies and templates. [https://github.com/open-policy-agent/gatekeeper/tree/master/library](https://github.com/open-policy-agent/gatekeeper/tree/master/library)

## Importing Libraries

Importing a library is also supported, a rego library should be placed in the `lib` folder.

`Konstraint` will then add the Rego from the library into the `libs` section of the `ConstraintTemplate`.

