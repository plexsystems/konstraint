# @title The title
#
# The description
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
# @matchExpression foo In bar,baz
# @matchExpression doggos Exists
package test

import future.keywords
import data.lib.libraryA

policyID := "P123456"

violation["msg"] {
    true # some comment with a trailing space 
}
