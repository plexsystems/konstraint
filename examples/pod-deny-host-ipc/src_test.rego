package pod_deny_host_ipc

test_hostipc_false {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostIPC": false,
        }
    }

    not pod_has_hostipc with input as input
}

test_hostipc_true {
    input := {
        "kind": "Pod",
        "metadata": {
            "name": "test-pod"
        },
        "spec": {
            "hostIPC": true,
        }
    }

    pod_has_hostipc with input as input
}
