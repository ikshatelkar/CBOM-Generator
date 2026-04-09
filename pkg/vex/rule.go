package vex

// Status values per the CISA VEX specification.
type Status string

// Justification values per the CISA VEX specification.
type Justification string

// Confidence indicates how certain the VEX evaluation result is.
type Confidence string

const (
	StatusAffected           Status = "affected"
	StatusNotAffected        Status = "not_affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

const (
	JustificationComponentNotPresent        Justification = "component_not_present"
	JustificationCodeNotReachable           Justification = "code_not_reachable"
	JustificationConfigurationNotVulnerable Justification = "configuration_not_vulnerable"
	JustificationRequiresSpecificEnv        Justification = "requires_specific_env"
	JustificationNone                       Justification = "none"
)

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// ComponentInfo holds the crypto properties of a detected component needed
// for VEX rule evaluation. It is extracted from model.INode before rules run.
type ComponentInfo struct {
	Algorithm string // e.g. "AES", "RSA", "SHA-1"
	Mode      string // e.g. "ECB", "CBC", "GCM"
	Padding   string // e.g. "PKCS1", "OAEP"
	KeySize   int    // in bits; 0 if unknown
	Primitive string // e.g. "hash", "block-cipher", "pke"
	Version   string // protocol version, e.g. "1.0", "1.1"
}

// VEXResult is the output of evaluating one vulnerability rule against one component.
type VEXResult struct {
	CVEID           string
	Status          Status
	Justification   Justification
	ImpactStatement string
	Confidence      Confidence
}

// VEXRuleFunc evaluates a single vulnerability ID against a component.
// Returns nil if this rule does not handle the given vulnID.
type VEXRuleFunc func(vulnID string, comp ComponentInfo) *VEXResult

// VEXRule pairs a human-readable description with its evaluation function.
// Rules are evaluated in registration order; the first non-nil result wins.
// To add a new rule, call registry.Register with a new VEXRule.
type VEXRule struct {
	ID          string      // e.g. "VEX-PQC", "VEX-HASH"
	Description string      // what this rule covers
	Evaluate    VEXRuleFunc // returns nil if rule does not apply
}

// VEXRuleRegistry holds all registered VEX evaluation rules.
type VEXRuleRegistry struct {
	rules []*VEXRule
}

// NewVEXRuleRegistry creates an empty registry.
func NewVEXRuleRegistry() *VEXRuleRegistry {
	return &VEXRuleRegistry{}
}

// Register adds a VEX rule to the registry.
func (r *VEXRuleRegistry) Register(rule *VEXRule) {
	r.rules = append(r.rules, rule)
}

// AllRules returns all registered rules.
func (r *VEXRuleRegistry) AllRules() []*VEXRule {
	return r.rules
}

// EvaluateAll runs all registered rules for a given vulnerability ID against a
// component. Returns the first matching result. Falls back to Rule 6
// (under_investigation) if no rule fires.
func (r *VEXRuleRegistry) EvaluateAll(vulnID string, comp ComponentInfo) VEXResult {
	for _, rule := range r.rules {
		if result := rule.Evaluate(vulnID, comp); result != nil {
			return *result
		}
	}

	// Rule 6 — insufficient data to determine exploitability.
	return VEXResult{
		CVEID:           vulnID,
		Status:          StatusUnderInvestigation,
		Justification:   JustificationNone,
		ImpactStatement: "Insufficient static analysis data to determine exploitability. Manual review recommended.",
		Confidence:      ConfidenceLow,
	}
}
