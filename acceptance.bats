#!/usr/bin/env bats

@test "[DOC] Generated documentation matches example documentation" {
  run ./build/konstraint doc examples --output examples/policies.md
  git diff --quiet -- examples/policies.md
}

@test "[DOC] Outputting documentation to a different output directory" {
  run ./build/konstraint doc examples --output test/doc/expected.md
  git diff --quiet -- test/doc/expected.md
}

@test "[CREATE] Creating constraints and templates matches examples" {
  run ./build/konstraint create examples
  git diff --quiet -- examples/container-images/constraint.yaml
  git diff --quiet -- examples/container-images/template.yaml
}

@test "[CREATE] Creating constraints using --output matches expected output" {
  run ./build/konstraint create examples --output test/create
  git diff --quiet -- test/create/constraint_ContainersLatestTag.yaml
  git diff --quiet -- test/create/template_ContainersLatestTag.yaml

  git diff --quiet -- test/create/constraint_ContainersResourceConstraints.yaml
  git diff --quiet -- test/create/template_ContainersResourceConstraints.yaml
}
