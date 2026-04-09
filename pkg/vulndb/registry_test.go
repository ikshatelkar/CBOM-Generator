package vulndb_test

import (
	"testing"

	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/vulndb"
)

func TestNewRegistry_StartsEmpty(t *testing.T) {
	r := vulndb.NewVulnRuleRegistry()
	if len(r.AllRules()) != 0 {
		t.Fatalf("expected empty registry, got %d rules", len(r.AllRules()))
	}
}

func TestRegister_AddsRules(t *testing.T) {
	r := vulndb.NewVulnRuleRegistry()
	r.Register(&vulndb.VulnRule{ID: "T-001", Match: func(model.INode) bool { return false }})
	r.Register(&vulndb.VulnRule{ID: "T-002", Match: func(model.INode) bool { return false }})

	if len(r.AllRules()) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(r.AllRules()))
	}
}

func TestEvaluate_ReturnsOnlyMatchingRules(t *testing.T) {
	r := vulndb.NewVulnRuleRegistry()
	r.Register(&vulndb.VulnRule{ID: "MATCH", Match: func(model.INode) bool { return true }})
	r.Register(&vulndb.VulnRule{ID: "SKIP", Match: func(model.INode) bool { return false }})

	node := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, model.DetectionLocation{})
	matched := r.Evaluate(node)

	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
	if matched[0].ID != "MATCH" {
		t.Errorf("expected rule MATCH, got %s", matched[0].ID)
	}
}

func TestEvaluate_EmptyRegistry_ReturnsNil(t *testing.T) {
	r := vulndb.NewVulnRuleRegistry()
	node := model.NewAlgorithm("MD5", model.PrimitiveHash, model.DetectionLocation{})
	matched := r.Evaluate(node)
	if len(matched) != 0 {
		t.Errorf("expected 0 matches from empty registry, got %d", len(matched))
	}
}
