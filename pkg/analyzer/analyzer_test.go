package analyzer_test

import (
	"testing"

	"github.com/cbom-scanner/pkg/analyzer"
	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/vulndb"
)

func testLoc() model.DetectionLocation {
	return model.DetectionLocation{FilePath: "/proj/Foo.java", Line: 10, Column: 1}
}

func fullRegistry(t *testing.T) *vulndb.VulnRuleRegistry {
	t.Helper()
	r := vulndb.NewVulnRuleRegistry()
	vulndb.RegisterAllRules(r)
	return r
}

// --------------------------------------------------------------------------
// BomRefForNode
// --------------------------------------------------------------------------

func TestBomRefForNode_Algorithm(t *testing.T) {
	node := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, testLoc())
	got := analyzer.BomRefForNode(node)
	want := "crypto-algorithm-AES-Foo.java-10"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBomRefForNode_Key(t *testing.T) {
	node := model.NewKey("RSA", model.KindPrivateKey, testLoc())
	got := analyzer.BomRefForNode(node)
	want := "crypto-key-RSA-Foo.java-10"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBomRefForNode_Protocol(t *testing.T) {
	node := model.NewProtocol("TLS", testLoc())
	got := analyzer.BomRefForNode(node)
	want := "crypto-protocol-TLS-Foo.java-10"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBomRefForNode_CipherSuite(t *testing.T) {
	node := model.NewCipherSuite("TLS_AES_256_GCM_SHA384", testLoc())
	got := analyzer.BomRefForNode(node)
	want := "crypto-ciphersuite-TLS_AES_256_GCM_SHA384-Foo.java-10"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --------------------------------------------------------------------------
// Analyze
// --------------------------------------------------------------------------

func TestAnalyze_FindsMD5Vulnerability(t *testing.T) {
	reg := fullRegistry(t)
	md5 := model.NewAlgorithm("MD5", model.PrimitiveHash, testLoc())

	findings := analyzer.Analyze([]model.INode{md5}, reg)

	ref := "crypto-algorithm-MD5-Foo.java-10"
	vulns, ok := findings[ref]
	if !ok {
		t.Fatalf("no findings for bom-ref %s", ref)
	}

	found := false
	for _, v := range vulns {
		if v.ID == "CBOM-HASH-001" {
			found = true
			if v.Severity != "critical" {
				t.Errorf("MD5 expected critical severity, got %q", v.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CBOM-HASH-001 in findings for MD5")
	}
}

func TestAnalyze_FindsSHA1Vulnerability(t *testing.T) {
	reg := fullRegistry(t)
	sha1 := model.NewAlgorithm("SHA-1", model.PrimitiveHash, testLoc())

	findings := analyzer.Analyze([]model.INode{sha1}, reg)

	ref := "crypto-algorithm-SHA-1-Foo.java-10"
	vulns, ok := findings[ref]
	if !ok {
		t.Fatalf("no findings for SHA-1 bom-ref %s", ref)
	}
	found := false
	for _, v := range vulns {
		if v.ID == "CBOM-HASH-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected CBOM-HASH-002 in findings for SHA-1")
	}
}

func TestAnalyze_SafeAlgorithmProducesNoFindings(t *testing.T) {
	reg := fullRegistry(t)
	sha256 := model.NewAlgorithm("SHA-256", model.PrimitiveHash, testLoc())

	findings := analyzer.Analyze([]model.INode{sha256}, reg)

	if len(findings) != 0 {
		t.Errorf("expected no findings for SHA-256, got %d entries", len(findings))
	}
}

func TestAnalyze_DeduplicatesSameNodeTwice(t *testing.T) {
	reg := fullRegistry(t)
	md5 := model.NewAlgorithm("MD5", model.PrimitiveHash, testLoc())

	// Pass the same node twice — should deduplicate
	findings := analyzer.Analyze([]model.INode{md5, md5}, reg)

	ref := "crypto-algorithm-MD5-Foo.java-10"
	count := 0
	for _, v := range findings[ref] {
		if v.ID == "CBOM-HASH-001" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected CBOM-HASH-001 exactly once (dedup), got %d", count)
	}
}

func TestAnalyze_MultipleNodes_IndependentFindings(t *testing.T) {
	reg := fullRegistry(t)
	md5 := model.NewAlgorithm("MD5", model.PrimitiveHash, testLoc())

	loc2 := model.DetectionLocation{FilePath: "/proj/Bar.java", Line: 5}
	sha1 := model.NewAlgorithm("SHA-1", model.PrimitiveHash, loc2)

	findings := analyzer.Analyze([]model.INode{md5, sha1}, reg)

	if _, ok := findings["crypto-algorithm-MD5-Foo.java-10"]; !ok {
		t.Error("expected findings for MD5 node")
	}
	if _, ok := findings["crypto-algorithm-SHA-1-Bar.java-5"]; !ok {
		t.Error("expected findings for SHA-1 node")
	}
}

func TestAnalyze_NilNodes_ReturnsEmptyMap(t *testing.T) {
	reg := fullRegistry(t)
	findings := analyzer.Analyze(nil, reg)
	if len(findings) != 0 {
		t.Errorf("expected empty map for nil nodes, got %d entries", len(findings))
	}
}

func TestAnalyze_EmptyRegistry_ReturnsNoFindings(t *testing.T) {
	reg := vulndb.NewVulnRuleRegistry() // empty
	md5 := model.NewAlgorithm("MD5", model.PrimitiveHash, testLoc())
	findings := analyzer.Analyze([]model.INode{md5}, reg)
	if len(findings) != 0 {
		t.Errorf("expected no findings with empty registry, got %d", len(findings))
	}
}
