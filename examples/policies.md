# Policies

|API Groups|Kinds|Description|
|---|---|---|
|apps, core|DaemonSet, Deployment, StatefulSet, Pod|Container images can not use the latest tag.|
|networking.istio.io/v1alpha3|VirtualService|VirtualServices must not be named virtual-service.|
