package container_deny_privileged

test_privileged {
  input := {
    "kind": "Pod",
    "metadata": {"name": "test"},
    "spec": {
      "containers": [{
        "securityContext": {
          "privileged": true
        }
      }]
    }
  }

  violations := violation with input as input
  count(violations) == 1
}

test_not_privileged {
  input := {
    "kind": "Pod",
    "metadata": {"name": "test"},
    "spec": {
      "containers": [{
        "securityContext": {
          "privileged": false
        }
      }]
    }
  }

  violations := violation with input as input
  count(violations) == 0
}

test_added_capability {
  input := {
    "kind": "Pod",
    "metadata": {"name": "test"},
    "spec": {
      "containers": [{
        "securityContext": {
          "capabilities": {
            "add": ["CAP_SYS_ADMIN"]
          }
        }
      }]
    }
  }

  violations := violation with input as input
  count(violations) == 1
}

test_null {
  input := {
    "kind": "Pod",
    "metadata": {"name": "test"},
  }

  violations := violation with input as input
  count(violations) == 0
}
