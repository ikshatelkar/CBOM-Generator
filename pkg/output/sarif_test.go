package output_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/output"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func sarifLoc() model.DetectionLocation {
	return model.DetectionLocation{FilePath: "/proj/Foo.java", Line: 10, Column: 5}
}

func generatorWithMD5() *output.Generator {
	gen := output.NewGenerator("/proj")
	algo := model.NewAlgorithm("MD5", model.PrimitiveHash, sarifLoc())
	gen.AddNodes([]model.INode{algo})
	gen.AnnotateVulnerabilities(map[string][]output.ComponentVuln{
		"crypto-algorithm-MD5-Foo.java-10": {
			{ID: "CBOM-HASH-001", Severity: "critical"},
		},
	})
	return gen
}

func testRuleMeta() map[string]output.SARIFRuleMeta {
	return map[string]output.SARIFRuleMeta{
		"CBOM-HASH-001": {
			Title:          "MD5 — Broken Hash Algorithm",
			Description:    "MD5 is broken.",
			Recommendation: "Use SHA-256.",
			Severity:       "critical",
			References:     []string{"CVE-2004-2761"},
		},
	}
}

// --------------------------------------------------------------------------
// WriteSARIF / GenerateSARIF
// --------------------------------------------------------------------------

func TestWriteSARIF_CreatesValidFile(t *testing.T) {
	gen := generatorWithMD5()
	path := t.TempDir() + "/results.sarif"

	if err := gen.WriteSARIF(path, testRuleMeta()); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
}

func TestGenerateSARIF_HasCorrectVersion(t *testing.T) {
	gen := generatorWithMD5()
	// Access via WriteSARIF round-trip
	path := t.TempDir() + "/out.sarif"
	if err := gen.WriteSARIF(path, testRuleMeta()); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	data, _ := os.ReadFile(path)
	var report map[string]interface{}
	json.Unmarshal(data, &report)

	if report["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", report["version"])
	}
}

func TestGenerateSARIF_ContainsRuleEntry(t *testing.T) {
	gen := generatorWithMD5()
	path := t.TempDir() + "/out.sarif"
	gen.WriteSARIF(path, testRuleMeta())

	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "CBOM-HASH-001") {
		t.Error("expected SARIF to contain rule ID CBOM-HASH-001")
	}
	if !strings.Contains(content, "MD5 — Broken Hash Algorithm") {
		t.Error("expected SARIF to contain rule title")
	}
}

func TestGenerateSARIF_ResultLevelIsMappedCorrectly(t *testing.T) {
	gen := generatorWithMD5()
	path := t.TempDir() + "/out.sarif"
	gen.WriteSARIF(path, testRuleMeta())

	data, _ := os.ReadFile(path)
	content := string(data)

	// critical → "error" in SARIF
	if !strings.Contains(content, `"level": "error"`) {
		t.Error(`expected SARIF level "error" for critical severity`)
	}
}

func TestGenerateSARIF_ContainsFileLocation(t *testing.T) {
	gen := generatorWithMD5()
	path := t.TempDir() + "/out.sarif"
	gen.WriteSARIF(path, testRuleMeta())

	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "Foo.java") {
		t.Error("expected SARIF to contain the source file path (Foo.java)")
	}
}

func TestGenerateSARIF_NoVulnerabilities_EmptyResults(t *testing.T) {
	gen := output.NewGenerator("/proj")
	algo := model.NewAlgorithm("SHA-256", model.PrimitiveHash, sarifLoc())
	gen.AddNodes([]model.INode{algo})
	// No vulnerabilities annotated

	path := t.TempDir() + "/out.sarif"
	gen.WriteSARIF(path, testRuleMeta())

	data, _ := os.ReadFile(path)
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	runs := raw["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results, ok := run["results"]
	if ok {
		arr, _ := results.([]interface{})
		if len(arr) != 0 {
			t.Errorf("expected empty results for un-annotated component, got %d", len(arr))
		}
	}
}

func TestGenerateSARIF_UnknownRuleID_StillEmitsResult(t *testing.T) {
	gen := output.NewGenerator("/proj")
	algo := model.NewAlgorithm("MD5", model.PrimitiveHash, sarifLoc())
	gen.AddNodes([]model.INode{algo})
	gen.AnnotateVulnerabilities(map[string][]output.ComponentVuln{
		"crypto-algorithm-MD5-Foo.java-10": {{ID: "UNKNOWN-999", Severity: "high"}},
	})

	path := t.TempDir() + "/out.sarif"
	// Pass empty meta — the rule has no metadata entry
	if err := gen.WriteSARIF(path, map[string]output.SARIFRuleMeta{}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "UNKNOWN-999") {
		t.Error("expected SARIF to still emit result for unknown rule ID")
	}
}
