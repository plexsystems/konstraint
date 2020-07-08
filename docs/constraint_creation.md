# How Constraints are Created

## Policy File Parsing

Konstraint only creates constraints for policies with `violation[]` rules in them, as that is required by Gatekeeper. If a policy does not have a violation rule in it, it is skipped.

## Importing Libraries

Libraries can be stored in a folder named `lib` or the name of the folder set with the `--lib` flag.

Libraries will be added to the `ConstraintTemplate` if and only if the associated policy imports the library. This helps prevent importing Rego code that will go unused.

## Resource Naming

The name of the ConstraintTemplate and Constraint are derived from the name of the folder that the policy was found in.

For example, a policy found in: `policies/pod-volume-size-limits/src.rego` generates the following in the `policies/pod-volume-size-limits` directory:

- `template.yaml` (defining a ConstraintTemplate)
  - kind: _ConstraintTemplate_
  - name: _podvolumesizelimits_
  - CRD kind (to add to Kubernetes API): _PodVolumeSizeLimits_

- `constraint.yaml` (implementing the above ConstraintTemplate)
  - kind: _PodVolumeSizeLimits_
  - name: _podvolumesizelimits_

While not technically required, the tool works best with a folder structure similar to how Gatekeeper itself [structures policies and templates](https://github.com/open-policy-agent/gatekeeper/tree/master/library).

## Annotating Rules

**Note: This feature is experimental.**

To further promote that the `.rego` file is the source of truth for policy, a form of block comments on each `violation` rule can be added that includes a human readable description of what the policy does. This comment block is used to set the matchers on the `Constraint` itself and to generate the policy documentation with `konstraint doc`.

```rego
# All images deployed to the cluster must not contain a latest tag.
# @Kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
  has_latest_tag

  msg := k8s.format(sprintf("(%s) %s: Images must not use the latest tag", [k8s.kind, k8s.name]))
}
```
