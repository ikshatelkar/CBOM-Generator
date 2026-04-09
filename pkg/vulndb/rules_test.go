package vulndb_test

import (
	"testing"

	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/vulndb"
)

// helpers

func newFullRegistry(t *testing.T) *vulndb.VulnRuleRegistry {
	t.Helper()
	r := vulndb.NewVulnRuleRegistry()
	vulndb.RegisterAllRules(r)
	return r
}

func testLoc() model.DetectionLocation {
	return model.DetectionLocation{FilePath: "test.java", Line: 1, Column: 1}
}

func assertFired(t *testing.T, id string, matched []*vulndb.VulnRule) {
	t.Helper()
	for _, r := range matched {
		if r.ID == id {
			return
		}
	}
	t.Errorf("expected rule %s to fire, but it did not (matched: %v)", id, ruleIDs(matched))
}

func assertNotFired(t *testing.T, id string, matched []*vulndb.VulnRule) {
	t.Helper()
	for _, r := range matched {
		if r.ID == id {
			t.Errorf("expected rule %s NOT to fire, but it did", id)
			return
		}
	}
}

func ruleIDs(rules []*vulndb.VulnRule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

// --------------------------------------------------------------------------
// Hash rules
// --------------------------------------------------------------------------

func TestRule_MD5_Fires(t *testing.T) {
	r := newFullRegistry(t)
	node := model.NewAlgorithm("MD5", model.PrimitiveHash, testLoc())
	assertFired(t, "CBOM-HASH-001", r.Evaluate(node))
}

func TestRule_MD5_CaseInsensitive(t *testing.T) {
	r := newFullRegistry(t)
	for _, name := range []string{"md5", "Md5", "MD5"} {
		node := model.NewAlgorithm(name, model.PrimitiveHash, testLoc())
		assertFired(t, "CBOM-HASH-001", r.Evaluate(node))
	}
}

func TestRule_MD5_DoesNotFireOnSHA256(t *testing.T) {
	r := newFullRegistry(t)
	node := model.NewAlgorithm("SHA-256", model.PrimitiveHash, testLoc())
	assertNotFired(t, "CBOM-HASH-001", r.Evaluate(node))
}

func TestRule_SHA1_Fires(t *testing.T) {
	r := newFullRegistry(t)
	for _, name := range []string{"SHA-1", "SHA1", "sha-1", "sha1"} {
		node := model.NewAlgorithm(name, model.PrimitiveHash, testLoc())
		assertFired(t, "CBOM-HASH-002", r.Evaluate(node))
	}
}

func TestRule_SHA1_DoesNotFireOnSHA256(t *testing.T) {
	r := newFullRegistry(t)
	node := model.NewAlgorithm("SHA-256", model.PrimitiveHash, testLoc())
	assertNotFired(t, "CBOM-HASH-002", r.Evaluate(node))
}

// --------------------------------------------------------------------------
// Cipher rules
// --------------------------------------------------------------------------

func TestRule_DES_Fires(t *testing.T) {
	r := newFullRegistry(t)
	node := model.NewAlgorithm("DES", model.PrimitiveBlockCipher, testLoc())
	assertFired(t, "CBOM-CIPHER-001", r.Evaluate(node))
}

func TestRule_DES_DoesNotFireOnAES(t *testing.T) {
	r := newFullRegistry(t)
	node := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, testLoc())
	assertNotFired(t, "CBOM-CIPHER-001", r.Evaluate(node))
}

func TestRule_RC4_Fires(t *testing.T) {
	r := newFullRegistry(t)
	for _, name := range []string{"RC4", "ARCFOUR", "rc4"} {
		node := model.NewAlgorithm(name, model.PrimitiveStreamCipher, testLoc())
		assertFired(t, "CBOM-CIPHER-003", r.Evaluate(node))
	}
}

// --------------------------------------------------------------------------
// Mode rules
// --------------------------------------------------------------------------

func TestRule_ECB_Fires(t *testing.T) {
	r := newFullRegistry(t)
	algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, testLoc())
	algo.Put(model.NewMode("ECB"))
	assertFired(t, "CBOM-MODE-001", r.Evaluate(algo))
}

func TestRule_ECB_DoesNotFireOnGCM(t *testing.T) {
	r := newFullRegistry(t)
	algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, testLoc())
	algo.Put(model.NewMode("GCM"))
	assertNotFired(t, "CBOM-MODE-001", r.Evaluate(algo))
}

// --------------------------------------------------------------------------
// Key size rules
// --------------------------------------------------------------------------

func TestRule_SmallRSAKey_Fires(t *testing.T) {
	r := newFullRegistry(t)
	key := model.NewKey("RSA", model.KindSecretKey, testLoc())
	key.Put(model.NewKeyLength(1024))
	assertFired(t, "CBOM-KEY-001", r.Evaluate(key))
}

func TestRule_AdequateRSAKey_DoesNotFireKeyRule(t *testing.T) {
	r := newFullRegistry(t)
	key := model.NewKey("RSA", model.KindSecretKey, testLoc())
	key.Put(model.NewKeyLength(4096))
	assertNotFired(t, "CBOM-KEY-001", r.Evaluate(key))
}

// --------------------------------------------------------------------------
// Rule set integrity
// --------------------------------------------------------------------------

func TestAllRules_UniqueIDs(t *testing.T) {
	r := newFullRegistry(t)
	seen := make(map[string]bool)
	for _, rule := range r.AllRules() {
		if seen[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		seen[rule.ID] = true
	}
}

func TestAllRules_RequiredFieldsNonEmpty(t *testing.T) {
	r := newFullRegistry(t)
	for _, rule := range r.AllRules() {
		if rule.ID == "" {
			t.Error("a rule has an empty ID")
		}
		if rule.Title == "" {
			t.Errorf("rule %s has an empty Title", rule.ID)
		}
		if rule.Severity == "" {
			t.Errorf("rule %s has an empty Severity", rule.ID)
		}
		if rule.Match == nil {
			t.Errorf("rule %s has a nil Match function", rule.ID)
		}
	}
}

func TestAllRules_ValidSeverityValues(t *testing.T) {
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	r := newFullRegistry(t)
	for _, rule := range r.AllRules() {
		if !valid[rule.Severity] {
			t.Errorf("rule %s has invalid severity %q", rule.ID, rule.Severity)
		}
	}
}
