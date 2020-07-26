package lib.security

dropped_capability(container, cap) {
  container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) {
  container.securityContext.capabilities.add[_] == cap
}

dropped_capability(psp, cap) {
  psp.spec.capabilities.drop[_] == cap
}

added_capability(psp, cap) {
  psp.spec.capabilities.add[_] == cap
}
