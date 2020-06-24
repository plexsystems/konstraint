# Examples

An example directory when working with `Konstraint`

The `pod-container-images` directory contains four files:

- src.rego
- src_test.rego
- constaint.yaml (auto-generated)
- template.yaml (auto-generated)

Running the following command from the root of the repository:

```shell
$ konstraint create examples
```

Will create both `template.yaml` and `constraint.yaml` based on the contents of `lib/kubernetes.rego` and `pod-container-images/src.rego`.

When a change is made to either `lib/kubernetes.rego` or `pod-container-images/src.rego` the `Konstraint` tool should be executed again.

Treat both `template.yaml` and `constraint.yaml` as artifacts generated from the rego policy.