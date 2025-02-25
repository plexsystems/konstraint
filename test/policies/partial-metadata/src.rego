# METADATA
# title: The title
# description: The description
# custom:
#   matchers:
#     namespaces:
#     - dev
#     - stage
#     - prod
package test_partialmetadata

import future.keywords.if
import data.lib.libraryA

policyID := "P123456"

violation if {
    true # some comment
}
