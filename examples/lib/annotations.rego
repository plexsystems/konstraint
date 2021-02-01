package lib.annotations
# Annotations helper library used to extract policy metadata information from annotation fields
# Usage:
#
# import data.lib.annotations 
# annotations = annotations.policy_annotations()
# 

import data.lib.core
import data.lib.pods

default paramsAnnotationField = "policy.konstraint.io/parameters"
default ignoreAnnotationField = "policy.konstraint.io/ignore"

all_annotations = return {
  return :=  object.union(object.get(core.resource.metadata, "annotations", {}), object.get(pods.pod.metadata, "annotations", {}))
} 