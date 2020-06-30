package policy

import data.lib.k8s

# VirtualServices must not be named virtual-service.
# @Kinds networking.istio.io/v1alpha3/VirtualService
violation[msg] {
  not virtualservice_name_allowed

  msg := k8s.format(sprintf("(%s) %s: VirtualServices must not be named virtual-service.", [k8s.kind, k8s.name]))
}

virtualservice_name_allowed {
  k8s.kind == "VirtualService"
  not k8s.name == "virtual-service"
}
