package policy

import data.lib.core

violation[msg] {
    core.kind == "Deployment"
    not service_selector_exists

    msg := core.format(sprintf("%s/%s: No service exists with same selectors", [core.kind, core.name]))
}

service_selector_exists {
    services := data.inventory.namespace[core.resource.metadata.namespace]["v1"]["Deployment"][_]

    core.resource.spec.template.metadata.labels == services.spec.selector
}
