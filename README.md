# Konstraint

[![Go Report Card](https://goreportcard.com/badge/github.com/plexsystems/konstraint)](https://goreportcard.com/report/github.com/plexsystems/konstraint)

![logo](images/logo.png)

Konstraint is a cli tool to assist with the creation and management of constraints when using [Gatekeeper](https://github.com/open-policy-agent/gatekeeper)

**NOTE: THIS TOOL IS CURRENTLY A WORK IN PROGRESS AND SUBJECT TO CHANGE**

## Installation

```
go get github.com/plexsystems/konstraint
```

## Usage

To create a `ConstraintTemplate` from a `Rego` policy, you can use the `template` command:

`konstraint template myrego.rego`

This will generate a `ConstraintTemplate` that includes the Rego policy

