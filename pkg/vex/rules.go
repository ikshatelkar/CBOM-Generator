package vex

import "strings"

// cveMapping maps internal vulnerability rule IDs to known public CVE identifiers.
// If a rule ID is not present here, the rule ID itself is used as the cve_id.
// To add a CVE mapping for a new rule, insert an entry here.
var cveMapping = map[string]string{
	"CBOM-HASH-001":    "CVE-2004-2761",  // MD5 collision
	"CBOM-CIPHER-003":  "CVE-2013-2566",  // RC4 statistical bias
	"CBOM-CIPHER-002":  "CVE-2016-2183",  // SWEET32 — 3DES birthday attack
	"CBOM-CIPHER-006":  "CVE-2016-2183",  // SWEET32 — Blowfish birthday attack
	"CBOM-TLS-002":     "CVE-2014-3566",  // POODLE — SSLv3
	"CBOM-TLS-003":     "CVE-2011-3389",  // BEAST — TLS 1.0
	"CBOM-SUITE-003":   "CVE-2015-0204",  // FREAK — EXPORT suites
	"CBOM-SUITE-004":   "CVE-2015-4000",  // LogJam — anonymous DH
	"CBOM-PADDING-001": "CVE-1998-0017",  // Bleichenbacher — PKCS#1 v1.5
	"CBOM-RNG-001":     "CVE-2013-6386",  // SHA1PRNG predictable seeding
	"CBOM-KDF-001":     "CVE-2016-2183",  // PBEWithMD5AndDES — broken primitives
}

// cveID returns the public CVE identifier for a rule ID, falling back to the rule ID.
func cveID(ruleID string) string {
	if cve, ok := cveMapping[ruleID]; ok {
		return cve
	}
	return ruleID
}

// RegisterAllVEXRules registers every VEX evaluation rule into the registry.
//
// Rules are evaluated in order; the first rule that returns a non-nil result wins.
// To add a new rule, append a registry.Register block in the relevant section.
func RegisterAllVEXRules(registry *VEXRuleRegistry) {

	// ==========================================================================
	// VEX-PQC: Post-quantum migration advisories
	//
	// These algorithms are not currently broken but are vulnerable to Shor's
	// algorithm on a large quantum computer. The threat is not yet present so
	// status is "under_investigation" with low confidence.
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-PQC",
		Description: "Post-quantum cryptography migration advisories (NIST IR 8547)",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			if !strings.HasPrefix(vulnID, "CBOM-PQC-") {
				return nil
			}
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          StatusUnderInvestigation,
				Justification:   JustificationRequiresSpecificEnv,
				ImpactStatement: "This algorithm is vulnerable to Shor's algorithm on a cryptographically relevant quantum computer. No such computer currently exists. Migration planning is recommended per NIST IR 8547.",
				Confidence:      ConfidenceLow,
			}
		},
	})

	// ==========================================================================
	// VEX-HASH: Broken and deprecated hash algorithms
	//
	// When one of our hash rules fires, the algorithm is definitively present
	// and in use, so the status is "affected" with high confidence.
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-HASH",
		Description: "Broken and deprecated hash algorithm rules",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			impacts := map[string]string{
				"CBOM-HASH-001": "MD5 is present and used for hashing. Known collision attacks allow two different inputs to produce the same digest, breaking integrity guarantees.",
				"CBOM-HASH-002": "SHA-1 is present and used for hashing. Chosen-prefix collision attacks (SHAttered) allow forged signatures and certificates.",
				"CBOM-HASH-003": "MD4 is present and used for hashing. MD4 is fully broken and collisions can be computed in milliseconds.",
				"CBOM-HASH-004": "MD2 is present and used for hashing. MD2 is obsolete and has known preimage and collision weaknesses.",
				"CBOM-HASH-005": "SHA-224 is present. While not currently broken, the digest length is marginally short for long-term use.",
				"CBOM-HASH-006": "RIPEMD-160 is present. This non-standard hash algorithm lacks NIST approval and may be deprecated by future standards.",
			}
			impact, ok := impacts[vulnID]
			if !ok {
				return nil
			}
			severity := ConfidenceHigh
			status := StatusAffected
			if vulnID == "CBOM-HASH-005" || vulnID == "CBOM-HASH-006" {
				status = StatusUnderInvestigation
				severity = ConfidenceMedium
			}
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          status,
				Justification:   JustificationNone,
				ImpactStatement: impact,
				Confidence:      severity,
			}
		},
	})

	// ==========================================================================
	// VEX-CIPHER: Broken and weak symmetric ciphers
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-CIPHER",
		Description: "Broken and weak symmetric cipher rules",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			impacts := map[string]string{
				"CBOM-CIPHER-001": "DES is present with a 56-bit key. Brute-force attacks are trivially feasible with modern hardware.",
				"CBOM-CIPHER-002": "3DES/TDEA is present. Its 64-bit block size makes it vulnerable to SWEET32 birthday attacks in long sessions.",
				"CBOM-CIPHER-003": "RC4 is present. Statistical biases in RC4's keystream allow practical plaintext recovery.",
				"CBOM-CIPHER-004": "RC2 is present. This export-grade cipher provides inadequate security and is not NIST-approved.",
				"CBOM-CIPHER-005": "IDEA is present. Its 64-bit block size introduces SWEET32 risk and it is not NIST-approved.",
				"CBOM-CIPHER-006": "Blowfish is present. Its 64-bit block size makes it susceptible to birthday attacks in high-volume sessions.",
				"CBOM-CIPHER-007": "A null or no-encryption algorithm is present. Data is transmitted or stored without confidentiality protection.",
			}
			impact, ok := impacts[vulnID]
			if !ok {
				return nil
			}
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          StatusAffected,
				Justification:   JustificationNone,
				ImpactStatement: impact,
				Confidence:      ConfidenceHigh,
			}
		},
	})

	// ==========================================================================
	// VEX-MODE: Unsafe cipher modes of operation
	//
	// RULE: IF component uses ECB mode → affected.
	// RULE: IF component uses GCM or CBC (non-ECB) → not_affected,
	//        justification = configuration_not_vulnerable.
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-MODE",
		Description: "Unsafe cipher mode rules — ECB vs safe alternatives",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			if vulnID != "CBOM-MODE-001" {
				return nil
			}
			mode := strings.ToUpper(comp.Mode)
			if mode == "GCM" || mode == "CCM" || mode == "CBC" || mode == "CTR" {
				// RULE 3: configuration_not_vulnerable — component uses a safe mode
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusNotAffected,
					Justification:   JustificationConfigurationNotVulnerable,
					ImpactStatement: "Component uses " + comp.Mode + " mode, not ECB. The ECB weakness does not apply.",
					Confidence:      ConfidenceHigh,
				}
			}
			if mode == "ECB" {
				// RULE 4: algorithm matches and is in use
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusAffected,
					Justification:   JustificationNone,
					ImpactStatement: "ECB mode is in use. Identical plaintext blocks produce identical ciphertext blocks, leaking data patterns.",
					Confidence:      ConfidenceHigh,
				}
			}
			// Mode unknown — Rule 6
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          StatusUnderInvestigation,
				Justification:   JustificationNone,
				ImpactStatement: "Cipher mode could not be determined from static analysis. Manual review recommended.",
				Confidence:      ConfidenceLow,
			}
		},
	})

	// ==========================================================================
	// VEX-PADDING: Dangerous padding schemes
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-PADDING",
		Description: "Dangerous RSA padding rules",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			if vulnID != "CBOM-PADDING-001" {
				return nil
			}
			padding := strings.ToUpper(comp.Padding)
			if strings.Contains(padding, "OAEP") {
				// RULE 3: OAEP padding is safe — configuration_not_vulnerable
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusNotAffected,
					Justification:   JustificationConfigurationNotVulnerable,
					ImpactStatement: "Component uses OAEP padding, which is not vulnerable to Bleichenbacher's attack.",
					Confidence:      ConfidenceHigh,
				}
			}
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          StatusAffected,
				Justification:   JustificationNone,
				ImpactStatement: "PKCS#1 v1.5 encryption padding is in use. Vulnerable to Bleichenbacher chosen-ciphertext and ROBOT padding oracle attacks.",
				Confidence:      ConfidenceHigh,
			}
		},
	})

	// ==========================================================================
	// VEX-TLS: Deprecated TLS/SSL protocol versions
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-TLS",
		Description: "Deprecated TLS/SSL protocol version rules",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			impacts := map[string]string{
				"CBOM-TLS-001": "SSLv2 is present. It has fundamental design flaws and has been prohibited since RFC 6176 (2011).",
				"CBOM-TLS-002": "SSLv3 is present. It is vulnerable to the POODLE attack (CVE-2014-3566), which allows plaintext recovery.",
				"CBOM-TLS-003": "TLS 1.0 is present. It is deprecated by RFC 8996 and susceptible to the BEAST attack (CVE-2011-3389).",
				"CBOM-TLS-004": "TLS 1.1 is present. It is deprecated by RFC 8996 and does not support modern AEAD cipher suites.",
			}
			impact, ok := impacts[vulnID]
			if !ok {
				return nil
			}
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          StatusAffected,
				Justification:   JustificationNone,
				ImpactStatement: impact,
				Confidence:      ConfidenceHigh,
			}
		},
	})

	// ==========================================================================
	// VEX-SUITE: Weak TLS cipher suites
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-SUITE",
		Description: "Weak and prohibited TLS cipher suite rules",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			impacts := map[string]string{
				"CBOM-SUITE-001": "An RC4-based cipher suite is in use. RC4 is prohibited by RFC 7465 due to statistical biases enabling plaintext recovery.",
				"CBOM-SUITE-002": "A NULL encryption cipher suite is in use. Traffic is transmitted with authentication but no confidentiality.",
				"CBOM-SUITE-003": "An EXPORT-grade cipher suite is in use. Weak 40/56-bit keys enable FREAK (CVE-2015-0204) downgrade attacks.",
				"CBOM-SUITE-004": "An anonymous cipher suite is in use. No server authentication is performed, enabling trivial man-in-the-middle attacks.",
				"CBOM-SUITE-005": "A DES-based cipher suite is in use. 56-bit keys are trivially brute-forceable.",
				"CBOM-SUITE-006": "A cipher suite with MD5 as MAC is in use. MD5 collision resistance is broken.",
			}
			impact, ok := impacts[vulnID]
			if !ok {
				return nil
			}
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          StatusAffected,
				Justification:   JustificationNone,
				ImpactStatement: impact,
				Confidence:      ConfidenceHigh,
			}
		},
	})

	// ==========================================================================
	// VEX-KEY: Insufficient key sizes
	//
	// RULE: IF key size is known and below threshold → affected.
	// RULE: IF key size is unknown → under_investigation.
	// CRYPTO-SPECIFIC: RSA key < 2048 → affected; RSA key >= 2048 → not_affected.
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-KEY",
		Description: "Insufficient cryptographic key size rules",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			type keyRule struct {
				threshold int
				impact    string
			}
			thresholds := map[string]keyRule{
				"CBOM-KEY-001": {2048, "RSA key is present with insufficient size. Keys below 2048 bits can be factored with publicly available tools."},
				"CBOM-KEY-002": {2048, "DSA key is present with insufficient size. Keys below 2048 bits do not meet the NIST minimum security requirement."},
				"CBOM-KEY-003": {256, "ECC key is present with insufficient size. Keys below 256 bits do not provide the minimum 112-bit security level."},
			}
			kr, ok := thresholds[vulnID]
			if !ok {
				if vulnID == "CBOM-KEY-004" {
					// AES-128 is informational — not currently broken
					return &VEXResult{
						CVEID:           cveID(vulnID),
						Status:          StatusUnderInvestigation,
						Justification:   JustificationNone,
						ImpactStatement: "AES-128 provides 128-bit security, which is currently sufficient. Grover's algorithm on a quantum computer would halve effective key length. No immediate threat.",
						Confidence:      ConfidenceMedium,
					}
				}
				return nil
			}
			if comp.KeySize > 0 && comp.KeySize < kr.threshold {
				// CRYPTO-SPECIFIC RULE: key size known and below threshold → affected
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusAffected,
					Justification:   JustificationNone,
					ImpactStatement: kr.impact,
					Confidence:      ConfidenceHigh,
				}
			}
			if comp.KeySize >= kr.threshold {
				// Key size is sufficient — this rule fired on detection but VEX confirms not affected
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusNotAffected,
					Justification:   JustificationConfigurationNotVulnerable,
					ImpactStatement: "Key size meets or exceeds the minimum threshold. Not vulnerable.",
					Confidence:      ConfidenceHigh,
				}
			}
			// Key size unknown — Rule 6
			return &VEXResult{
				CVEID:           cveID(vulnID),
				Status:          StatusUnderInvestigation,
				Justification:   JustificationNone,
				ImpactStatement: "Key size could not be determined from static analysis. Manual review recommended.",
				Confidence:      ConfidenceLow,
			}
		},
	})

	// ==========================================================================
	// VEX-RNG: Random Number Generator vulnerabilities
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-RNG",
		Description: "Weak or non-standard PRNG algorithms (e.g. SHA1PRNG)",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			if vulnID != "CBOM-RNG-001" {
				return nil
			}
			// SHA1PRNG is explicitly named — the weak algorithm is confirmed present
			if strings.EqualFold(comp.Algorithm, "SHA1PRNG") {
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusAffected,
					Justification:   JustificationNone,
					ImpactStatement: "SHA1PRNG is explicitly requested via SecureRandom.getInstance(\"SHA1PRNG\"). This PRNG uses the deprecated SHA-1 hash and has platform-dependent seeding behaviour that can produce predictable output when improperly seeded.",
					Confidence:      ConfidenceHigh,
				}
			}
			return nil
		},
	})

	// ==========================================================================
	// VEX-IMPL: CWE-1240 risky implementation vulnerabilities
	// Covers NullCipher, weak PBE schemes, and hardcoded IVs.
	// ==========================================================================
	registry.Register(&VEXRule{
		ID:          "VEX-IMPL",
		Description: "Cryptographic primitives with risky implementations (CWE-1240)",
		Evaluate: func(vulnID string, comp ComponentInfo) *VEXResult {
			switch vulnID {
			case "CBOM-NULL-001":
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusAffected,
					Justification:   JustificationNone,
					ImpactStatement: "NullCipher performs no encryption. Data is passed through unchanged, providing zero confidentiality. Any sensitive data processed by NullCipher is effectively transmitted or stored in plaintext.",
					Confidence:      ConfidenceHigh,
				}
			case "CBOM-KDF-001":
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusAffected,
					Justification:   JustificationNone,
					ImpactStatement: "PBE scheme combines two broken primitives. The weak hash provides inadequate key stretching and the deprecated cipher provides insufficient encryption strength. Derived keys can be recovered with moderate computational effort.",
					Confidence:      ConfidenceHigh,
				}
			case "CBOM-IV-001":
				return &VEXResult{
					CVEID:           cveID(vulnID),
					Status:          StatusAffected,
					Justification:   JustificationNone,
					ImpactStatement: "A static all-zero IV makes encryption deterministic. Identical plaintexts always produce identical ciphertexts, enabling pattern analysis. In CBC mode this also exposes the first block to chosen-plaintext attacks.",
					Confidence:      ConfidenceMedium,
				}
			}
			return nil
		},
	})
}
