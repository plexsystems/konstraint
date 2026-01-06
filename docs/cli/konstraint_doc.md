## konstraint doc

Generate documentation from Rego policies

```
konstraint doc <dir> [flags]
```

### Examples

```
Generate the documentation
	konstraint doc

Save the documentation to a specific directory
	konstraint doc --output docs/policies.md

Set the URL where the policies are hosted at
	konstraint doc --url https://github.com/plexsystems/konstraint
```

### Options

```
  -h, --help                   help for doc
      --include-comments       Include comments from the rego source in the documentation
      --no-rego                Do not include the Rego in the policy documentation
  -o, --output string          Output location (including filename) for the policy documentation (default "policies.md")
      --rego-version string    Rego version for parsing policies (v0, v1) (default "v0")
      --strip-v0-imports       Strip v0 compatibility imports from documentation: import future.keywords[.if|.in|.every|.contains], import rego.v1 (only valid with --rego-version v1)
      --template-file string   File to read the template from (default: "")
      --url string             The URL where the policy files are hosted at (e.g. https://github.com/policies)
```

### SEE ALSO

* [konstraint](konstraint.md)	 - Konstraint

