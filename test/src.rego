# @title The title
#
# The description
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
# @matchExpression foo In bar,baz
# @matchExpression doggos Exists
# @namespaces dev stage prod
# @excludedNamespaces kube-system gatekeeper-system
# @parameter super string -- super duper cool parameter
# -- with a description on two strings
package test

import data.lib.libraryA

policyID := "P123456"

violation[{"msg": "msg"}] {
    true # some comment with a trailing space 
}
