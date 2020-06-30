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
# @Kinds core/Pod apps/Deployment apps/DaemonSet
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

	expectedGroups := []string{"core", "apps"}
	for _, expectedGroup := range expectedGroups {
		if !contains(actual[0].APIGroups, expectedGroup) {
			t.Errorf("expected policy block to contain '%v' APIGroup, but was not found.", expectedGroup)
		}
	}

	expectedKinds := []string{"Pod", "DaemonSet", "Deployment"}
	for _, expectedKind := range expectedKinds {
		if !contains(actual[0].Kinds, expectedKind) {
			t.Errorf("expected policy block to contain '%v' APIGroup, but was not found.", expectedKind)
		}
	}
}
