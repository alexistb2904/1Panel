package service

import "testing"

func TestContainerAllowedDoesNotTreatOwnedNameAsIDPrefix(t *testing.T) {
	allowed := map[string]struct{}{"deadbeefdead": {}}
	if containerAllowed(allowed, "deadbeefdead0123456789abcdef", "victim") {
		t.Fatal("a crafted 12-character owned container name must never authorize another container by ID prefix")
	}
}

func TestContainerAllowedRequiresExactCanonicalNameOrFullID(t *testing.T) {
	allowed := map[string]struct{}{
		"project-api": {},
		"0123456789abcdef": {},
	}
	if !containerAllowed(allowed, "", "project-api") { t.Fatal("exact owned name should authorize") }
	if !containerAllowed(allowed, "0123456789abcdef", "") { t.Fatal("canonical full ID resolved from an owned name should authorize") }
	if containerAllowed(allowed, "0123456789abcdef9999", "other") { t.Fatal("ID prefix/suffix similarity must not authorize") }
}
