# Policies

|API Groups|Kinds|Description|
|---|---|---|
|apps, core|DaemonSet, Deployment, StatefulSet, Pod|Container images can not use the latest tag.|
|apps, core|DaemonSet, Deployment, StatefulSet, Pod|EmptyDir volume mounts must specify a size limit.|
