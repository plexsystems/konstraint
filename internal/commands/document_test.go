package commands

import "testing"

func TestGetPolicyCommentBlocks_NoKinds(t *testing.T) {
	policy := `
# Description
violation[msg] {
	false
}`

	policyBytes := []byte(policy)
	actual, err := getPolicyCommentBlocks(policyBytes)
	if err != nil {
		t.Fatal("get policy comment blocks:", err)
	}

	if len(actual) > 0 {
		t.Error("expected no comment blocks, but comment blocks were returned")
	}
}

func TestGetPolicyCommentBlocks(t *testing.T) {
	policy := `
# First description
# @Kinds core/Pods apps/Deployments apps/DaemonSet
violation[msg] {
	false
}`

	policyBytes := []byte(policy)
	actual, err := getPolicyCommentBlocks(policyBytes)
	if err != nil {
		t.Fatal("get policy comment blocks:", err)
	}

	if len(actual) == 0 {
		t.Errorf("expected policy block to exist, but one did not.")
	}

	expectedAPIGroupCount := 2
	if len(actual[0].APIGroups) != expectedAPIGroupCount {
		t.Errorf("expected %v APIGroups to exists but %v were found", expectedAPIGroupCount, len(actual[0].APIGroups))
	}

	if !contains(actual[0].APIGroups, "core") {
		t.Errorf("expected policy block to contain 'core' APIGroup, but was not found.")
	}

	if !contains(actual[0].APIGroups, "apps") {
		t.Errorf("expected policy block to contain 'apps' APIGroup, but was not found.")
	}

	if !contains(actual[0].Kinds, "Pods") {
		t.Errorf("expected policy block to contain 'Pods' Kind, but was not found.")
	}

	if !contains(actual[0].Kinds, "Deployments") {
		t.Errorf("expected policy block to contain 'Deployments' Kind, but was not found.")
	}
}
