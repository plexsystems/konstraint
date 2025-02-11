#!/usr/bin/env bats

@test "[DOC] Generated documentation matches example documentation" {
  run ./build/konstraint doc examples --output examples/policies.md
  [ "$status" -eq 0 ]
  git diff --quiet -- examples/policies.md
}

@test "[DOC] Generated documentation without Rego matches example documentation" {
  run ./build/konstraint doc --no-rego examples --output examples/policies-no-rego.md
  [ "$status" -eq 0 ]
  git diff --quiet -- examples/policies-no-rego.md
}

@test "[CREATE] Creating constraints and templates matches examples" {
  run ./build/konstraint create examples
  [ "$status" -eq 0 ]
  git diff --quiet -- examples/
}

@test "[CREATE] Creating constraints using --output matches expected output" {
  run ./build/konstraint create test --output test
  [ "$status" -eq 0 ]
  git diff --quiet -- test/
}

@test "[CREATE] Creating constraints using --constraint-custom-template-file, --constraint-template-custom-template-file and --output matches expected output" {
  run ./build/konstraint create test --constraint-custom-template-file internal/commands/constraint_template.tpl --constraint-template-custom-template-file internal/commands/constrainttemplate_template.tpl --partial-constraints --output test/custom
  [ "$status" -eq 0 ]
  git diff --quiet -- test/custom
}
