#!/usr/bin/env bats

@test "[DOC] Generated documentation matches example documentation" {
  run ./build/konstraint doc examples --output examples/policies.md
  git diff --quiet -- examples/policies.md
}

@test "[CREATE] Creating constraints and templates matches examples" {
  run ./build/konstraint create examples
  git diff --quiet -- examples/
}

@test "[CREATE] Creating constraints using --output matches expected output" {
  run ./build/konstraint create test --output test
  git diff --quiet -- test/
}
