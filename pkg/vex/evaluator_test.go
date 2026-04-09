package vex_test

import (
	"testing"

	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/output"
	"github.com/cbom-scanner/pkg/vex"
)

func evalLoc() model.DetectionLocation {
	return model.DetectionLocation{FilePath: "/proj/Foo.java", Line: 1, Column: 1}
}

func fullVEXRegistry(t *testing.T) *vex.VEXRuleRegistry {
	t.Helper()
	reg := vex.NewVEXRuleRegistry()
	vex.RegisterAllVEXRules(reg)
	return reg
}

func TestEvaluate_ProducesVEXBlockForMD5Finding(t *testing.T) {
	reg := fullVEXRegistry(t)
	md5 := model.NewAlgorithm("MD5", model.PrimitiveHash, evalLoc())
	ref := "crypto-algorithm-MD5-Foo.java-1"

	findings := map[string][]output.ComponentVuln{
		ref: {{ID: "CBOM-HASH-001", Severity: "critical"}},
	}

	result := vex.Evaluate([]model.INode{md5}, findings, reg)

	block, ok := result[ref]
	if !ok {
		t.Fatalf("expected a VEX block for ref %s", ref)
	}
	if len(block.Vulnerabilities) == 0 {
		t.Fatal("expected at least one VEX entry in the block")
	}
	entry := block.Vulnerabilities[0]
	if entry.CVEID == "" {
		t.Error("VEX entry has empty CVE ID")
	}
	if entry.VEXStatus == "" {
		t.Error("VEX entry has empty vex_status")
	}
	if entry.Confidence == "" {
		t.Error("VEX entry has empty confidence")
	}
}

func TestEvaluate_NilInputs_ReturnsEmptyMap(t *testing.T) {
	reg := fullVEXRegistry(t)
	result := vex.Evaluate(nil, nil, reg)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil inputs, got %d entries", len(result))
	}
}

func TestEvaluate_FindingWithNoMatchingNode_IsSkipped(t *testing.T) {
	reg := fullVEXRegistry(t)

	// Finding references a bom-ref that has no corresponding node in the list
	findings := map[string][]output.ComponentVuln{
		"ghost-ref": {{ID: "CBOM-HASH-001", Severity: "critical"}},
	}

	result := vex.Evaluate(nil, findings, reg)

	if _, ok := result["ghost-ref"]; ok {
		t.Error("expected ghost-ref to be skipped (no matching node)")
	}
}

func TestEvaluate_MultipleNodesProduceIndependentBlocks(t *testing.T) {
	reg := fullVEXRegistry(t)

	loc1 := model.DetectionLocation{FilePath: "/proj/A.java", Line: 1}
	loc2 := model.DetectionLocation{FilePath: "/proj/B.java", Line: 2}
	md5 := model.NewAlgorithm("MD5", model.PrimitiveHash, loc1)
	sha1 := model.NewAlgorithm("SHA-1", model.PrimitiveHash, loc2)

	ref1 := "crypto-algorithm-MD5-A.java-1"
	ref2 := "crypto-algorithm-SHA-1-B.java-2"

	findings := map[string][]output.ComponentVuln{
		ref1: {{ID: "CBOM-HASH-001", Severity: "critical"}},
		ref2: {{ID: "CBOM-HASH-002", Severity: "high"}},
	}

	result := vex.Evaluate([]model.INode{md5, sha1}, findings, reg)

	if _, ok := result[ref1]; !ok {
		t.Errorf("expected VEX block for ref1 (%s)", ref1)
	}
	if _, ok := result[ref2]; !ok {
		t.Errorf("expected VEX block for ref2 (%s)", ref2)
	}
}

func TestEvaluate_EmptyFindingsMap_ProducesEmptyResult(t *testing.T) {
	reg := fullVEXRegistry(t)
	md5 := model.NewAlgorithm("MD5", model.PrimitiveHash, evalLoc())

	result := vex.Evaluate([]model.INode{md5}, map[string][]output.ComponentVuln{}, reg)

	if len(result) != 0 {
		t.Errorf("expected empty result for empty findings, got %d entries", len(result))
	}
}
