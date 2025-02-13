# METADATA
# title: The title
# description: The description
# custom:
#   parameters:
#     super:
#       type: string
#       description: |-
#         super duper cool parameter with a description
#         on two lines.
#   matchers:
#     excludedNamespaces:
#     - kube-system
#     - gatekeeper-system
#     kinds:
#     - apiGroups:
#       - ""
#       kinds:
#       - Pod
#     - apiGroups:
#       - apps
#       kinds:
#       - DaemonSet
#       - Deployment
#       - StatefulSet
#     labelSelector:
#       matchExpressions:
#       - key: foo
#         operator: In
#         values:
#         - bar
#         - baz
#       - key: doggos
#         operator: Exists
#     namespaces:
#     - dev
#     - stage
#     - prod
package test

import future.keywords.if
import data.lib.libraryA

policyID := "P123456"

violation if {
    true # some comment
}
