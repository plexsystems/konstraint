package create

import data.lib.core

# @title Images must not use the latest tag
#
# Using the latest tag on images can cause unexpected problems in production. By specifing a pinned version
# we can have higher confidence that our applications are immutable and do not change unexpectedly.
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
    msg := core.format(sprintf("%s/%s: Images must not use the latest tag", [core.kind, core.name]))
}
