package vex_test

import (
	"testing"

	"github.com/cbom-scanner/pkg/vex"
)

func TestEvaluateAll_EmptyRegistry_ReturnsFallback(t *testing.T) {
	reg := vex.NewVEXRuleRegistry()
	result := reg.EvaluateAll("CBOM-HASH-001", vex.ComponentInfo{Algorithm: "MD5"})

	if result.Status != vex.StatusUnderInvestigation {
		t.Errorf("expected under_investigation fallback, got %s", result.Status)
	}
	if result.Confidence != vex.ConfidenceLow {
		t.Errorf("expected low confidence fallback, got %s", result.Confidence)
	}
}

func TestEvaluateAll_NonMatchingRule_ReturnsFallback(t *testing.T) {
	reg := vex.NewVEXRuleRegistry()
	reg.Register(&vex.VEXRule{
		ID:       "NEVER",
		Evaluate: func(vulnID string, comp vex.ComponentInfo) *vex.VEXResult { return nil },
	})

	result := reg.EvaluateAll("CBOM-HASH-001", vex.ComponentInfo{Algorithm: "MD5"})

	if result.Status != vex.StatusUnderInvestigation {
		t.Errorf("expected under_investigation when no rule fires, got %s", result.Status)
	}
}

func TestEvaluateAll_ReturnsFirstMatchingRule(t *testing.T) {
	reg := vex.NewVEXRuleRegistry()
	reg.Register(&vex.VEXRule{
		ID: "FIRST",
		Evaluate: func(vulnID string, comp vex.ComponentInfo) *vex.VEXResult {
			return &vex.VEXResult{
				CVEID:      vulnID,
				Status:     vex.StatusAffected,
				Confidence: vex.ConfidenceHigh,
			}
		},
	})
	reg.Register(&vex.VEXRule{
		ID: "SECOND",
		Evaluate: func(vulnID string, comp vex.ComponentInfo) *vex.VEXResult {
			return &vex.VEXResult{
				CVEID:      vulnID,
				Status:     vex.StatusFixed,
				Confidence: vex.ConfidenceHigh,
			}
		},
	})

	result := reg.EvaluateAll("X", vex.ComponentInfo{})

	if result.Status != vex.StatusAffected {
		t.Errorf("expected first rule result (affected), got %s", result.Status)
	}
}

func TestEvaluateAll_SkipsNilResultAndTakesNext(t *testing.T) {
	reg := vex.NewVEXRuleRegistry()
	reg.Register(&vex.VEXRule{
		ID:       "SKIP",
		Evaluate: func(vulnID string, comp vex.ComponentInfo) *vex.VEXResult { return nil },
	})
	reg.Register(&vex.VEXRule{
		ID: "HIT",
		Evaluate: func(vulnID string, comp vex.ComponentInfo) *vex.VEXResult {
			return &vex.VEXResult{Status: vex.StatusNotAffected, Confidence: vex.ConfidenceMedium}
		},
	})

	result := reg.EvaluateAll("X", vex.ComponentInfo{})

	if result.Status != vex.StatusNotAffected {
		t.Errorf("expected not_affected from second rule, got %s", result.Status)
	}
}

func TestAllVEXRules_RegisterWithNonEmptyIDs(t *testing.T) {
	reg := vex.NewVEXRuleRegistry()
	vex.RegisterAllVEXRules(reg)

	if len(reg.AllRules()) == 0 {
		t.Fatal("expected at least one VEX rule to be registered")
	}
	for _, rule := range reg.AllRules() {
		if rule.ID == "" {
			t.Error("a VEX rule has an empty ID")
		}
		if rule.Evaluate == nil {
			t.Errorf("VEX rule %s has nil Evaluate function", rule.ID)
		}
	}
}
