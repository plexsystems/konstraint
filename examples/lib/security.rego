package lib.security

import future.keywords.if

dropped_capability(container, cap) if {
	lower(container.securityContext.capabilities.drop[_]) == lower(cap)
}

dropped_capability(psp, cap) if {
	lower(psp.spec.requiredDropCapabilities[_]) == lower(cap)
}

added_capability(container, cap) if {
	lower(container.securityContext.capabilities.add[_]) == lower(cap)
}

added_capability(psp, cap) if {
	lower(psp.spec.allowedCapabilities[_]) == lower(cap)
}

added_capability(psp, cap) if {
	lower(psp.spec.defaultAddCapabilities[_]) == lower(cap)
}
