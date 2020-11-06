package required_labels

test_not_missing {
    in := {
        "metadata": {
            "labels": {
                "test": "test"
            }
        }
    }

    missing := missing_labels with input as in
    count(missing) == 0
}

test_missing_gk {
    in := {
        "review": {
            "object": {
                "metadata": {
                    "labels": {
                        "test": "test"
                    }
                }
            }
        },        
        "parameters": {
            "labels": ["one", "two"]
        }
    }

    missing := missing_labels with input as in
    count(missing) == 2
}

test_missing_not_gk {
    in := {
        "metadata": {
            "labels": {
                "test": "test"
            }
        }
    }
    p := {
        "labels": ["test", "two"]
    }

    missing := missing_labels with input as in with data.parameters as p
    count(missing) == 1
}
