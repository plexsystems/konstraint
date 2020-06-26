package policy

import data.lib.k8s

# EmptyDir volume mounts must specify a size limit.
# @Kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod
violation[msg] {
  volumes_emptydir_size_limit_required

  msg := k8s.format(sprintf("(%s) %s: Volume mounts of type emptyDir must set a size limit", [k8s.kind, k8s.name]))
}

volumes_emptydir_size_limit_required {
  k8s.missing_field(k8s.volumes[_].emptyDir, "sizeLimit")
}
