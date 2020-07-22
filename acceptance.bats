#!/usr/bin/env bats

@test "[DOC] Generated documentation matches example documentation" {
  run ./konstraint doc examples --output examples/policies.md
  git diff --quiet -- examples/policies.md
}

@test "[DOC] Outputting documentation to a different output directory" {
  run ./konstraint doc examples --output test/doc/expected.md
  git diff --quiet -- test/doc/expected.md
}

@test "[CREATE] Created constraints and templates matches examples" {
  run ./konstraint create examples
  git diff --quiet -- examples/container-images/constraint.yaml
  git diff --quiet -- examples/container-images/template.yaml
}
