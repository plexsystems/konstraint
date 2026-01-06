## konstraint create

Create Gatekeeper constraints from Rego policies

```
konstraint create <dir> [flags]
```

### Examples

```
Create constraints in the same directories as the policies
	konstraint create examples

Save the constraints in a specific directory
	konstraint create examples --output generated-constraints

Create constraints with the Gatekeeper enforcement action set to dryrun
	konstraint create examples --dryrun
```

### Options

```
      --constraint-custom-template-file string            Path to a custom template file to generate constraints
      --constraint-template-custom-template-file string   Path to a custom template file to generate constraint templates
      --constraint-template-version string                Set the version of ConstraintTemplates (default "v1")
  -d, --dryrun                                            Set the enforcement action of the constraints to dryrun, overriding the enforcement setting
  -h, --help                                              help for create
      --log-level string                                  Set a log level. Options: error, info, debug, trace (default "info")
  -o, --output string                                     Specify an output directory for the Gatekeeper resources
      --partial-constraints                               Generate partial Constraints for policies with parameters
      --rego-version string                               Set the Rego version for parsing and template generation (v0, v1) (default "v0")
      --skip-constraints                                  Skip generation of constraints
      --strip-v0-imports                                  Strip v0 compatibility imports from generated templates: import future.keywords[.if|.in|.every|.contains], import rego.v1 (only valid with --rego-version v1)
```

### SEE ALSO

* [konstraint](konstraint.md)	 - Konstraint

