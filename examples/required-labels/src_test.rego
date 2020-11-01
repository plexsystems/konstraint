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

test_missing {
    in := {
        "metadata": {
            "labels": {
                "test": "test"
            }
        },
        "parameters": {
            "labels": ["one", "two"]
        }
    }

    missing := missing_labels with input as in
    count(missing) == 2
}
