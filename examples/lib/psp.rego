package lib.psps

import data.lib.core
import future.keywords.contains
import future.keywords.if
import future.keywords.in

# PodSecurityPolicies are not namespace scoped, so the default PSPs included
# in managed Kubernetes offerings cannot be excluded using the normal
# methods in Gatekeeper.
is_exception if {
	exceptions := {
		"gce.privileged", # GKE
		"gce.persistent-volume-binder", # GKE
		"gce.event-exporter", # GKE
		"gce.gke-metrics-agent", # GKE
		"gce.unprivileged-addon", # GKE
		"gce.fluentd-gke", # GKE
		"gce.fluentd-gcp", # GKE
	}

	core.name in exceptions
}

psps contains psp if {
	lower(core.kind) = "podsecuritypolicy"
	not is_exception
	psp = core.resource
}
