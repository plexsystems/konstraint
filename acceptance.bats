#!/usr/bin/env bats

@test "[DOC] Generated documentation matches example documentation" {
  run ./konstraint doc examples --output examples/policies.md
  git diff --quiet -- examples/policies.md
}
