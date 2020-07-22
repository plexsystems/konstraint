# Policies

|Name|Rule Types|API Groups|Kinds|Description|
|---|---|---|---|---|
|[Container Images](../../examples/container-images)|violation|apps, core|DaemonSet, Deployment, StatefulSet, Pod|Container images can not use the latest tag.|
|[Containers Resource Constraints Required](../../examples/containers-resource-constraints-required)|violation|apps, core|DaemonSet, Deployment, StatefulSet, Pod|Containers must have resource constraints specified.|
