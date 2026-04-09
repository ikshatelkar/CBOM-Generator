package vulndb

import "github.com/cbom-scanner/pkg/model"

// MatchFunc returns true if this VulnRule applies to the given node.
type MatchFunc func(node model.INode) bool

// VulnRule defines a single cryptographic weakness detection rule.
//
// To add a new rule, create a new VulnRule and call registry.Register.
// Rules are grouped by category in separate files:
//   - rules_hashes.go  — broken/weak hash algorithms
//   - rules_ciphers.go — broken/weak symmetric ciphers, modes, padding
//   - rules_tls.go     — deprecated TLS/SSL versions and weak cipher suites
//   - rules_keys.go    — insufficient key sizes
//   - rules_pqc.go     — quantum-computing migration advisories
type VulnRule struct {
	ID             string    // unique identifier, e.g. "CBOM-HASH-001"
	Category       string    // "hash" | "cipher" | "mode" | "tls" | "key" | "pqc"
	Title          string    // short human-readable title
	Description    string    // full description of the weakness
	Severity       string    // "critical" | "high" | "medium" | "low" | "info"
	References     []string  // NIST SP, RFC, CVE, or other authoritative sources
	Recommendation string    // remediation guidance
	Match          MatchFunc // returns true if this rule fires on the given node
}

// VulnRuleRegistry holds all registered vulnerability rules.
type VulnRuleRegistry struct {
	rules []*VulnRule
}

// NewVulnRuleRegistry creates an empty registry.
func NewVulnRuleRegistry() *VulnRuleRegistry {
	return &VulnRuleRegistry{}
}

// Register adds a rule to the registry.
func (r *VulnRuleRegistry) Register(rule *VulnRule) {
	r.rules = append(r.rules, rule)
}

// AllRules returns all registered rules.
func (r *VulnRuleRegistry) AllRules() []*VulnRule {
	return r.rules
}

// Evaluate runs all registered rules against the given node and returns
// every rule whose Match function returns true.
func (r *VulnRuleRegistry) Evaluate(node model.INode) []*VulnRule {
	var matched []*VulnRule
	for _, rule := range r.rules {
		if rule.Match(node) {
			matched = append(matched, rule)
		}
	}
	return matched
}
