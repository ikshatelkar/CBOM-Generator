package vulndb

import (
	"strings"

	"github.com/cbom-scanner/pkg/model"
)

// RegisterAllRules registers every vulnerability rule into the registry.
// All rules live here so you can see the full rule set in one place.
// To add a new rule, append a registry.Register block in the relevant section.
func RegisterAllRules(registry *VulnRuleRegistry) {

	// ==========================================================================
	// HASH ALGORITHMS
	// Covers broken or deprecated cryptographic hash functions.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-HASH-001: MD5
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-HASH-001",
		Category:    "hash",
		Title:       "MD5 — Broken Hash Algorithm",
		Description: "MD5 produces a 128-bit digest and is vulnerable to collision attacks since 2004. It must not be used for integrity checking, digital signatures, or authentication.",
		Severity:    "critical",
		References:  []string{"NIST SP 800-131A Rev 2", "RFC 6151", "CVE-2004-2761"},
		Recommendation: "Replace with SHA-256 or SHA-3 (SHA3-256 or stronger).",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "MD5")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-HASH-002: SHA-1
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-HASH-002",
		Category:    "hash",
		Title:       "SHA-1 — Deprecated Hash Algorithm",
		Description: "SHA-1 produces a 160-bit digest and is vulnerable to chosen-prefix collision attacks (SHAttered, 2017). NIST has disallowed SHA-1 for digital signatures and most uses since 2013.",
		Severity:    "high",
		References:  []string{"NIST SP 800-131A Rev 2", "RFC 9155", "https://shattered.io"},
		Recommendation: "Replace with SHA-256, SHA-384, or SHA-3.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "SHA-1" || name == "SHA1"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-HASH-003: MD4
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-HASH-003",
		Category:    "hash",
		Title:       "MD4 — Cryptographically Broken Hash",
		Description: "MD4 is fully broken and must not be used in any security-sensitive context. Collisions can be found in seconds on consumer hardware.",
		Severity:    "critical",
		References:  []string{"RFC 6150"},
		Recommendation: "Replace with SHA-256 or SHA-3.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "MD4")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-HASH-004: MD2
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-HASH-004",
		Category:    "hash",
		Title:       "MD2 — Obsolete Hash Algorithm",
		Description: "MD2 is an obsolete hash algorithm with known collisions and preimage weaknesses. It was deprecated in RFC 6149.",
		Severity:    "critical",
		References:  []string{"RFC 6149"},
		Recommendation: "Replace with SHA-256 or SHA-3.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "MD2")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-HASH-005: SHA-224
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-HASH-005",
		Category:    "hash",
		Title:       "SHA-224 — Marginally Short Digest Length",
		Description: "SHA-224 produces a 224-bit digest. While not currently broken, NIST recommends preferring SHA-256 or longer for new implementations to ensure adequate long-term security margin.",
		Severity:    "info",
		References:  []string{"NIST SP 800-131A Rev 2"},
		Recommendation: "Prefer SHA-256 or SHA-384 for stronger security margins.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "SHA-224" || name == "SHA224"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-HASH-006: RIPEMD-160
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-HASH-006",
		Category:    "hash",
		Title:       "RIPEMD-160 — Non-Standard, Aging Hash Algorithm",
		Description: "RIPEMD-160 is not recommended by NIST and does not carry the same security assurance as SHA-2 or SHA-3. It also uses a 64-bit block size susceptible to length-extension attacks in naive use.",
		Severity:    "medium",
		References:  []string{"NIST SP 800-131A Rev 2"},
		Recommendation: "Replace with SHA-256 or SHA-3.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			return strings.HasPrefix(strings.ToUpper(a.Name), "RIPEMD")
		},
	})

	// ==========================================================================
	// SYMMETRIC CIPHERS, MODES, AND PADDING
	// Covers broken/weak encryption algorithms, unsafe modes of operation,
	// and dangerous padding schemes.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-CIPHER-001: DES
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-CIPHER-001",
		Category:    "cipher",
		Title:       "DES — Broken Symmetric Cipher",
		Description: "DES uses a 56-bit key and is vulnerable to brute-force attacks. It was publicly cracked in 1998 in under 24 hours. NIST has withdrawn DES approval.",
		Severity:    "critical",
		References:  []string{"NIST SP 800-131A Rev 2", "FIPS 46-3 (withdrawn)"},
		Recommendation: "Replace with AES-256-GCM.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			return strings.ToUpper(a.Name) == "DES"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-CIPHER-002: 3DES / TDEA
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-CIPHER-002",
		Category:    "cipher",
		Title:       "3DES/TDEA — Deprecated Symmetric Cipher",
		Description: "Triple-DES has an effective security of only 112 bits and a 64-bit block size making it vulnerable to the SWEET32 birthday attack. NIST disallowed 3DES for new use in 2018 and for all use after 2023.",
		Severity:    "high",
		References:  []string{"NIST SP 800-131A Rev 2", "NIST SP 800-67 Rev 2", "CVE-2016-2183"},
		Recommendation: "Replace with AES-256-GCM.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "3DES" || name == "TDEA" || name == "DESEDE" ||
				name == "DESEDE3" || name == "TRIPLE-DES" || name == "TRIPLEDES" ||
				strings.Contains(name, "3DES") || strings.Contains(name, "TDEA")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-CIPHER-003: RC4
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-CIPHER-003",
		Category:    "cipher",
		Title:       "RC4 — Broken Stream Cipher",
		Description: "RC4 has multiple statistical biases that allow plaintext recovery and is prohibited in TLS by RFC 7465. It must not be used in any security context.",
		Severity:    "critical",
		References:  []string{"RFC 7465", "NIST SP 800-131A Rev 2"},
		Recommendation: "Replace with AES-256-GCM or ChaCha20-Poly1305.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "RC4" || name == "ARCFOUR"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-CIPHER-004: RC2
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-CIPHER-004",
		Category:    "cipher",
		Title:       "RC2 — Weak Symmetric Cipher",
		Description: "RC2 is an export-grade cipher historically deployed with 40-bit keys. It is not approved by NIST for any security use.",
		Severity:    "high",
		References:  []string{"NIST SP 800-131A Rev 2"},
		Recommendation: "Replace with AES-256-GCM.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			return strings.EqualFold(a.Name, "RC2")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-CIPHER-005: IDEA
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-CIPHER-005",
		Category:    "cipher",
		Title:       "IDEA — Non-Standard, Aging Block Cipher",
		Description: "IDEA uses a 64-bit block size making it vulnerable to SWEET32 birthday attacks in long sessions, and is not approved by NIST.",
		Severity:    "high",
		References:  []string{"NIST SP 800-131A Rev 2"},
		Recommendation: "Replace with AES-256-GCM.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			return strings.EqualFold(a.Name, "IDEA")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-CIPHER-006: Blowfish
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-CIPHER-006",
		Category:    "cipher",
		Title:       "Blowfish — 64-bit Block Size (SWEET32 Risk)",
		Description: "Blowfish uses a 64-bit block size. When large amounts of data are encrypted under the same key, birthday attacks (SWEET32) become practical, allowing plaintext recovery.",
		Severity:    "medium",
		References:  []string{"CVE-2016-2183", "https://sweet32.info"},
		Recommendation: "Replace with AES-256-GCM or ChaCha20-Poly1305.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			return strings.EqualFold(a.Name, "Blowfish")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-CIPHER-007: Null / No Encryption
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-CIPHER-007",
		Category:    "cipher",
		Title:       "Null / No Encryption — Critical Misconfiguration",
		Description: "A null cipher or no-encryption algorithm provides no confidentiality. Data is transmitted or stored in plaintext. This is a severe security misconfiguration.",
		Severity:    "critical",
		References:  []string{"NIST SP 800-131A Rev 2"},
		Recommendation: "Enable proper encryption using AES-256-GCM or ChaCha20-Poly1305.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "NULL" || name == "NONE" || name == "NOENCRYPTION"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-MODE-001: ECB mode
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-MODE-001",
		Category:    "mode",
		Title:       "ECB Mode — No Semantic Security",
		Description: "Electronic Code Book (ECB) mode encrypts each block independently with no initialisation vector or chaining. Identical plaintext blocks produce identical ciphertext blocks, leaking data patterns. This is illustrated by the 'ECB penguin' example.",
		Severity:    "high",
		References:  []string{"NIST SP 800-38A"},
		Recommendation: "Replace with AES-GCM (authenticated encryption) or AES-CBC with a random IV and a separate MAC.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			modeNode, has := a.HasChildOfKind(model.KindMode)
			if !has {
				return false
			}
			return strings.EqualFold(modeNode.AsString(), "ECB")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-PADDING-001: PKCS#1 v1.5 encryption padding
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-PADDING-001",
		Category:    "padding",
		Title:       "PKCS#1 v1.5 Encryption Padding — Bleichenbacher Attack",
		Description: "RSA encryption with PKCS#1 v1.5 padding is vulnerable to Bleichenbacher's 1998 chosen-ciphertext attack and related padding oracle attacks (ROBOT, DROWN). Adaptive chosen-ciphertext attacks can recover the plaintext.",
		Severity:    "high",
		References:  []string{"CVE-1998-0017", "RFC 8017 §7.2", "https://robotattack.org"},
		Recommendation: "Use RSA-OAEP (PKCS#1 v2.2 / RFC 8017 §7.1) for RSA encryption.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			padNode, has := a.HasChildOfKind(model.KindPadding)
			if !has {
				return false
			}
			pad := strings.ToUpper(padNode.AsString())
			return pad == "PKCS1" || pad == "PKCS1PADDING" ||
				strings.Contains(pad, "PKCS1V1") || pad == "PKCS#1"
		},
	})

	// ==========================================================================
	// TLS / SSL PROTOCOLS AND CIPHER SUITES
	// Covers deprecated protocol versions and weak/prohibited cipher suites.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-TLS-001: SSLv2
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-TLS-001",
		Category:    "tls",
		Title:       "SSLv2 — Severely Broken Protocol",
		Description: "SSL 2.0 has fundamental design flaws including weak MAC construction, no protection against cipher downgrade, and no session termination security. It has been prohibited by RFC 6176 since 2011.",
		Severity:    "critical",
		References:  []string{"RFC 6176", "NIST SP 800-52 Rev 2"},
		Recommendation: "Disable SSLv2 entirely. Use TLS 1.3 (TLS 1.2 as a minimum).",
		Match: func(node model.INode) bool {
			p, ok := node.(*model.Protocol)
			if !ok {
				return false
			}
			if vNode, has := p.HasChildOfKind(model.KindVersion); has {
				v := strings.ToUpper(vNode.AsString())
				if v == "2" || v == "2.0" || v == "SSLV2" || v == "SSL2" || v == "SSL_V2" {
					return true
				}
			}
			name := strings.ToUpper(p.Name)
			return strings.Contains(name, "SSLV2") || strings.Contains(name, "SSL2")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-TLS-002: SSLv3
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-TLS-002",
		Category:    "tls",
		Title:       "SSLv3 — POODLE Attack Vulnerability",
		Description: "SSL 3.0 is vulnerable to the POODLE attack (CVE-2014-3566), which allows an attacker to recover plaintext from SSL 3.0-encrypted connections. Prohibited by RFC 7568 since 2015.",
		Severity:    "critical",
		References:  []string{"RFC 7568", "CVE-2014-3566", "NIST SP 800-52 Rev 2"},
		Recommendation: "Disable SSLv3 entirely. Use TLS 1.3 (TLS 1.2 as a minimum).",
		Match: func(node model.INode) bool {
			p, ok := node.(*model.Protocol)
			if !ok {
				return false
			}
			if vNode, has := p.HasChildOfKind(model.KindVersion); has {
				v := strings.ToUpper(vNode.AsString())
				if v == "3" || v == "3.0" || v == "SSLV3" || v == "SSL3" || v == "SSL_V3" {
					return true
				}
			}
			name := strings.ToUpper(p.Name)
			return strings.Contains(name, "SSLV3") || strings.Contains(name, "SSL3")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-TLS-003: TLS 1.0
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-TLS-003",
		Category:    "tls",
		Title:       "TLS 1.0 — Deprecated Protocol",
		Description: "TLS 1.0 is deprecated by RFC 8996 (2021). It is susceptible to the BEAST attack (CVE-2011-3389) and does not support modern AEAD cipher suites. Major browsers and services have dropped support.",
		Severity:    "high",
		References:  []string{"RFC 8996", "CVE-2011-3389", "NIST SP 800-52 Rev 2"},
		Recommendation: "Upgrade to TLS 1.3. TLS 1.2 is acceptable as a temporary minimum.",
		Match: func(node model.INode) bool {
			p, ok := node.(*model.Protocol)
			if !ok {
				return false
			}
			if vNode, has := p.HasChildOfKind(model.KindVersion); has {
				v := strings.ToUpper(vNode.AsString())
				if v == "1" || v == "1.0" || v == "TLSV1" || v == "TLS1" || v == "TLS_V1" || v == "TLS1.0" {
					return true
				}
			}
			name := strings.ToUpper(p.Name)
			return name == "TLSV1" || name == "TLS1" ||
				strings.Contains(name, "TLSV1.0") || strings.Contains(name, "TLS1.0")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-TLS-004: TLS 1.1
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-TLS-004",
		Category:    "tls",
		Title:       "TLS 1.1 — Deprecated Protocol",
		Description: "TLS 1.1 is deprecated by RFC 8996 (2021). It does not support AEAD cipher suites and relies on CBC with implicit IV, making it vulnerable to timing attacks.",
		Severity:    "high",
		References:  []string{"RFC 8996", "NIST SP 800-52 Rev 2"},
		Recommendation: "Upgrade to TLS 1.3. TLS 1.2 is acceptable as a temporary minimum.",
		Match: func(node model.INode) bool {
			p, ok := node.(*model.Protocol)
			if !ok {
				return false
			}
			if vNode, has := p.HasChildOfKind(model.KindVersion); has {
				v := strings.ToUpper(vNode.AsString())
				if v == "1.1" || v == "TLSV1.1" || v == "TLS1.1" || v == "TLS_V1_1" {
					return true
				}
			}
			name := strings.ToUpper(p.Name)
			return strings.Contains(name, "TLSV1.1") || strings.Contains(name, "TLS1.1") ||
				strings.Contains(name, "TLS1_1")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-SUITE-001: Cipher suite — RC4
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-SUITE-001",
		Category:    "tls",
		Title:       "Cipher Suite Uses RC4",
		Description: "Cipher suites that use RC4 for bulk encryption are prohibited by RFC 7465. RC4 has statistical biases that allow practical plaintext recovery.",
		Severity:    "critical",
		References:  []string{"RFC 7465"},
		Recommendation: "Use TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3).",
		Match: func(node model.INode) bool {
			cs, ok := node.(*model.CipherSuite)
			if !ok {
				return false
			}
			return strings.Contains(strings.ToUpper(cs.Name), "RC4")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-SUITE-002: Cipher suite — NULL encryption
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-SUITE-002",
		Category:    "tls",
		Title:       "Cipher Suite With NULL Encryption",
		Description: "NULL encryption cipher suites provide authentication but no confidentiality — all application data is transmitted in plaintext.",
		Severity:    "critical",
		References:  []string{"NIST SP 800-52 Rev 2"},
		Recommendation: "Use cipher suites with strong AEAD (AES-GCM or ChaCha20-Poly1305).",
		Match: func(node model.INode) bool {
			cs, ok := node.(*model.CipherSuite)
			if !ok {
				return false
			}
			name := strings.ToUpper(cs.Name)
			return strings.Contains(name, "_NULL_") || strings.HasSuffix(name, "_NULL")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-SUITE-003: Cipher suite — EXPORT grade
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-SUITE-003",
		Category:    "tls",
		Title:       "Export-Grade Cipher Suite (FREAK / LogJam)",
		Description: "Export cipher suites use intentionally weakened 40-bit or 56-bit keys mandated by 1990s US export regulations. They enable FREAK (CVE-2015-0204) and LogJam (CVE-2015-4000) downgrade attacks.",
		Severity:    "critical",
		References:  []string{"CVE-2015-0204", "CVE-2015-4000"},
		Recommendation: "Remove all EXPORT cipher suites from the TLS configuration.",
		Match: func(node model.INode) bool {
			cs, ok := node.(*model.CipherSuite)
			if !ok {
				return false
			}
			return strings.Contains(strings.ToUpper(cs.Name), "EXPORT")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-SUITE-004: Cipher suite — Anonymous (no authentication)
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-SUITE-004",
		Category:    "tls",
		Title:       "Anonymous Cipher Suite (No Server Authentication)",
		Description: "Anonymous key exchange cipher suites (DH_anon, ECDH_anon) perform no server authentication, making connections trivially vulnerable to man-in-the-middle attacks.",
		Severity:    "critical",
		References:  []string{"NIST SP 800-52 Rev 2"},
		Recommendation: "Use certificate-authenticated cipher suites only.",
		Match: func(node model.INode) bool {
			cs, ok := node.(*model.CipherSuite)
			if !ok {
				return false
			}
			name := strings.ToUpper(cs.Name)
			return strings.Contains(name, "_ANON_") || strings.HasPrefix(name, "TLS_DH_ANON") ||
				strings.HasPrefix(name, "TLS_ECDH_ANON")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-SUITE-005: Cipher suite — DES
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-SUITE-005",
		Category:    "tls",
		Title:       "Cipher Suite Uses DES",
		Description: "DES-based cipher suites provide only 56-bit security, which is trivially brute-forceable with modern hardware.",
		Severity:    "critical",
		References:  []string{"NIST SP 800-131A Rev 2"},
		Recommendation: "Use TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256.",
		Match: func(node model.INode) bool {
			cs, ok := node.(*model.CipherSuite)
			if !ok {
				return false
			}
			name := strings.ToUpper(cs.Name)
			return strings.Contains(name, "_DES_") || strings.Contains(name, "_3DES_") ||
				strings.HasSuffix(name, "_DES") || strings.HasSuffix(name, "_3DES")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-SUITE-006: Cipher suite — MD5 MAC
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-SUITE-006",
		Category:    "tls",
		Title:       "Cipher Suite Uses MD5 as MAC",
		Description: "Cipher suites using MD5 as the MAC algorithm rely on a broken hash function with known collision attacks.",
		Severity:    "high",
		References:  []string{"RFC 6151", "NIST SP 800-131A Rev 2"},
		Recommendation: "Use cipher suites with SHA-256 HMAC or AEAD (which has no separate MAC).",
		Match: func(node model.INode) bool {
			cs, ok := node.(*model.CipherSuite)
			if !ok {
				return false
			}
			return strings.HasSuffix(strings.ToUpper(cs.Name), "_MD5")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-SUITE-007: Cipher suite — SHA-1 MAC
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-SUITE-007",
		Category:    "tls",
		Title:       "Cipher Suite Uses SHA-1 as MAC",
		Description: "TLS cipher suites ending in _SHA use SHA-1 as the HMAC algorithm (e.g. TLS_RSA_WITH_AES_128_CBC_SHA). SHA-1 is deprecated by NIST SP 800-131A Rev 2 and RFC 9155. These legacy suites should be replaced with AEAD cipher suites that use SHA-256 or stronger.",
		Severity:    "medium",
		References:  []string{"NIST SP 800-131A Rev 2", "RFC 9155", "RFC 8996"},
		Recommendation: "Replace with AEAD cipher suites: TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3), or TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2).",
		Match: func(node model.INode) bool {
			cs, ok := node.(*model.CipherSuite)
			if !ok {
				return false
			}
			name := strings.ToUpper(cs.Name)
			// Match suites ending in _SHA (SHA-1) but NOT _SHA256, _SHA384, _SHA512
			return strings.HasSuffix(name, "_SHA") &&
				!strings.HasSuffix(name, "_SHA256") &&
				!strings.HasSuffix(name, "_SHA384") &&
				!strings.HasSuffix(name, "_SHA512")
		},
	})

	// ==========================================================================
	// KEY SIZES
	// Covers cryptographic keys whose size falls below current NIST minimums.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-KEY-001: RSA key < 2048 bits
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-KEY-001",
		Category:    "key",
		Title:       "RSA Key Size Below 2048 Bits",
		Description: "RSA keys shorter than 2048 bits do not meet the current NIST minimum security requirement (112-bit security). Keys below 1024 bits are trivially factorable with publicly available tools.",
		Severity:    "high",
		References:  []string{"NIST SP 800-131A Rev 2", "NIST SP 800-57 Part 1 Rev 5"},
		Recommendation: "Use RSA keys of at least 3072 bits for current deployments, or 4096 bits for long-term key protection.",
		Match: func(node model.INode) bool {
			k, ok := node.(*model.Key)
			if !ok {
				return false
			}
			if !strings.EqualFold(k.Name, "RSA") {
				return false
			}
			klNode, has := k.HasChildOfKind(model.KindKeyLength)
			if !has {
				return false
			}
			ip, ok := klNode.(*model.IntProperty)
			return ok && ip.Value > 0 && ip.Value < 2048
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-KEY-002: DSA key < 2048 bits
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-KEY-002",
		Category:    "key",
		Title:       "DSA Key Size Below 2048 Bits",
		Description: "DSA keys shorter than 2048 bits do not meet the NIST minimum security requirement. Additionally, DSA requires a high-quality random nonce per signature; nonce reuse completely breaks the private key.",
		Severity:    "high",
		References:  []string{"NIST SP 800-131A Rev 2", "NIST SP 800-57 Part 1 Rev 5"},
		Recommendation: "Use DSA with at least 2048-bit keys, or migrate to ECDSA with curve P-256 or stronger.",
		Match: func(node model.INode) bool {
			k, ok := node.(*model.Key)
			if !ok {
				return false
			}
			if !strings.EqualFold(k.Name, "DSA") {
				return false
			}
			klNode, has := k.HasChildOfKind(model.KindKeyLength)
			if !has {
				return false
			}
			ip, ok := klNode.(*model.IntProperty)
			return ok && ip.Value > 0 && ip.Value < 2048
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-KEY-003: ECC key < 256 bits
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-KEY-003",
		Category:    "key",
		Title:       "ECC Key Size Below 256 Bits",
		Description: "Elliptic curve keys shorter than 256 bits (e.g. P-192, K-163) do not provide the minimum 112-bit security level required by NIST for current use.",
		Severity:    "medium",
		References:  []string{"NIST SP 800-131A Rev 2", "NIST SP 800-57 Part 1 Rev 5"},
		Recommendation: "Use P-256 (NIST) or Curve25519 as a minimum. Prefer P-384 for long-term key material.",
		Match: func(node model.INode) bool {
			k, ok := node.(*model.Key)
			if !ok {
				return false
			}
			name := strings.ToUpper(k.Name)
			isEC := strings.Contains(name, "EC") || strings.Contains(name, "ECDH") ||
				strings.Contains(name, "ECDSA") || strings.Contains(name, "ELLIPTIC")
			if !isEC {
				return false
			}
			klNode, has := k.HasChildOfKind(model.KindKeyLength)
			if !has {
				return false
			}
			ip, ok := klNode.(*model.IntProperty)
			return ok && ip.Value > 0 && ip.Value < 256
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-KEY-004: AES-128 (informational)
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-KEY-004",
		Category:    "key",
		Title:       "AES-128 — Consider Upgrading to AES-256",
		Description: "AES-128 currently provides sufficient security (128-bit security level). However, Grover's algorithm on a quantum computer halves the effective key length to 64 bits. NIST recommends AES-256 for long-lived data and post-quantum preparedness.",
		Severity:    "info",
		References:  []string{"NIST SP 800-131A Rev 2", "NIST IR 8547"},
		Recommendation: "Prefer AES-256 for new implementations, especially for data requiring long-term confidentiality.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			if !strings.EqualFold(a.Name, "AES") {
				return false
			}
			klNode, has := a.HasChildOfKind(model.KindKeyLength)
			if !has {
				return false
			}
			ip, ok := klNode.(*model.IntProperty)
			return ok && ip.Value == 128
		},
	})

	// ==========================================================================
	// POST-QUANTUM CRYPTOGRAPHY (PQC) MIGRATION ADVISORIES
	// Algorithms broken by Shor's or Grover's algorithm on a large quantum computer.
	// Severity is "low" — quantum threat is not yet present but migration planning
	// is required per NIST IR 8547.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-PQC-001: RSA
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-PQC-001",
		Category:    "pqc",
		Title:       "RSA — Quantum-Vulnerable (Shor's Algorithm)",
		Description: "RSA's security relies on the hardness of integer factorisation. Shor's algorithm solves this in polynomial time on a cryptographically relevant quantum computer. NIST IR 8547 designates RSA as requiring migration.",
		Severity:    "low",
		References:  []string{"NIST IR 8547", "NIST SP 800-131A Rev 2"},
		Recommendation: "Plan migration to NIST-approved post-quantum algorithms: ML-KEM (FIPS 203) for key encapsulation, ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "RSA")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-PQC-002: DSA
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-PQC-002",
		Category:    "pqc",
		Title:       "DSA — Quantum-Vulnerable (Shor's Algorithm)",
		Description: "DSA's security relies on the discrete logarithm problem in finite fields, which Shor's algorithm solves in polynomial time on a quantum computer.",
		Severity:    "low",
		References:  []string{"NIST IR 8547"},
		Recommendation: "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "DSA")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-PQC-003: ECDH / X25519 / X448
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-PQC-003",
		Category:    "pqc",
		Title:       "ECDH — Quantum-Vulnerable Key Exchange (Shor's Algorithm)",
		Description: "ECDH and related elliptic curve key agreement schemes rely on the elliptic curve discrete logarithm problem, which Shor's algorithm breaks in polynomial time on a quantum computer.",
		Severity:    "low",
		References:  []string{"NIST IR 8547"},
		Recommendation: "Plan migration to ML-KEM (FIPS 203) for key encapsulation.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "ECDH" || name == "ECDHC" || name == "X25519" || name == "X448"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-PQC-004: ECDSA / Ed25519 / Ed448
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-PQC-004",
		Category:    "pqc",
		Title:       "ECDSA — Quantum-Vulnerable Signature (Shor's Algorithm)",
		Description: "ECDSA and EdDSA rely on the elliptic curve discrete logarithm problem, which is broken by Shor's algorithm on a sufficiently powerful quantum computer.",
		Severity:    "low",
		References:  []string{"NIST IR 8547"},
		Recommendation: "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "ECDSA" || name == "ED25519" || name == "ED448"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-PQC-005: Classic Diffie-Hellman (DH)
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:          "CBOM-PQC-005",
		Category:    "pqc",
		Title:       "DH (Diffie-Hellman) — Quantum-Vulnerable Key Exchange",
		Description: "Classic Diffie-Hellman key exchange relies on the discrete logarithm problem in finite fields, which Shor's algorithm solves in polynomial time on a quantum computer.",
		Severity:    "low",
		References:  []string{"NIST IR 8547"},
		Recommendation: "Plan migration to ML-KEM (FIPS 203) for key encapsulation.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			name := strings.ToUpper(a.Name)
			return name == "DH" || name == "DIFFIE-HELLMAN" || name == "DIFFIEHELLMAN"
		},
	})

	// ==========================================================================
	// KEY DERIVATION FUNCTIONS
	// Covers weak or misconfigured KDF usages.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-KDF-002: PBKDF2 with weak hash function (SHA-1 or MD5)
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:       "CBOM-KDF-002",
		Category: "kdf",
		Title:    "PBKDF2 With Weak Hash Function (SHA-1 or MD5)",
		Description: "PBKDF2WithHmacSHA1 and PBKDF2WithHmacMD5 use deprecated hash functions " +
			"as their underlying PRF. SHA-1 has been disallowed by NIST SP 800-131A Rev 2 for " +
			"most uses since 2013, and MD5 is cryptographically broken. Using a weak hash in " +
			"PBKDF2 reduces the security of the derived key and makes the KDF more susceptible " +
			"to GPU/ASIC-accelerated brute-force attacks.",
		Severity:   "high",
		References: []string{"NIST SP 800-132", "NIST SP 800-131A Rev 2", "RFC 8018"},
		Recommendation: "Replace with PBKDF2WithHmacSHA256 or PBKDF2WithHmacSHA512. " +
			"In Python, pass hashes.SHA256() as the algorithm argument to PBKDF2HMAC.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			upper := strings.ToUpper(a.Name)
			return (strings.Contains(upper, "PBKDF2") || strings.Contains(upper, "PBKDF")) &&
				(strings.Contains(upper, "SHA1") || strings.Contains(upper, "SHA-1") ||
					strings.Contains(upper, "MD5"))
		},
	})

	// ==========================================================================
	// RANDOM NUMBER GENERATORS
	// Covers weak or non-cryptographic PRNGs used in security-sensitive contexts.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-RNG-001: SHA1PRNG
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:       "CBOM-RNG-001",
		Category: "rng",
		Title:    "SHA1PRNG — Weak Pseudo-Random Number Generator",
		Description: "SHA1PRNG is a non-standard PRNG provided by the Sun/Oracle security provider. " +
			"It uses SHA-1 (deprecated since 2013) as its core digest function, and its seeding " +
			"behaviour is inconsistent and platform-dependent across JVM implementations. " +
			"Predictable output has been demonstrated when the PRNG is improperly seeded.",
		Severity:       "high",
		References:     []string{"CWE-338", "NIST SP 800-131A Rev 2", "CVE-2013-6386"},
		Recommendation: "Replace with new SecureRandom() (JVM default) or SecureRandom.getInstanceStrong() to guarantee a platform-appropriate CSPRNG.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "SHA1PRNG")
		},
	})

	// ==========================================================================
	// CWE-1240: USE OF A CRYPTOGRAPHIC PRIMITIVE WITH A RISKY IMPLEMENTATION
	// Covers null ciphers, weak PBE schemes, and hardcoded IVs.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-NULL-001: NullCipher
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:       "CBOM-NULL-001",
		Category: "cipher",
		Title:    "NullCipher — No Encryption Performed",
		Description: "NullCipher is a Java cipher that performs no encryption or decryption. " +
			"Any data passed through it is returned unchanged. Using it in production code " +
			"completely disables confidentiality, making it equivalent to sending plaintext.",
		Severity:       "critical",
		References:     []string{"CWE-1240", "CWE-327"},
		Recommendation: "Replace NullCipher with a strong authenticated cipher such as AES/GCM/NoPadding.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "NullCipher")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-KDF-001: PBEWithMD5AndDES / PBEWithSHA1AndRC2
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:       "CBOM-KDF-001",
		Category: "kdf",
		Title:    "Weak PBE Scheme — Broken Hash and Cipher Combined",
		Description: "PBEWithMD5AndDES and PBEWithSHA1AndRC2 combine two deprecated primitives: " +
			"a broken hash function (MD5 or SHA-1) with a broken cipher (DES or RC2). " +
			"The resulting key derivation and encryption provide minimal security against modern attacks.",
		Severity:       "critical",
		References:     []string{"CWE-1240", "NIST SP 800-131A Rev 2", "CWE-327"},
		Recommendation: "Replace with PBKDF2WithHmacSHA256 for key derivation, combined with AES-256-GCM for encryption.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			upper := strings.ToUpper(a.Name)
			return strings.HasPrefix(upper, "PBEWITHMD5") ||
				strings.HasPrefix(upper, "PBEWITHSHA1AND") ||
				strings.HasPrefix(upper, "PBEWITHSHA-1AND")
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-IV-001: Hardcoded zero IV via new IvParameterSpec(new byte[...])
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:       "CBOM-IV-001",
		Category: "cipher",
		Title:    "Hardcoded Zero IV — Static Initialization Vector",
		Description: "Constructing IvParameterSpec with a freshly allocated byte array " +
			"(new byte[16]) results in an all-zero IV. A static IV with CBC or other " +
			"IV-dependent modes makes encryption deterministic: identical plaintexts " +
			"always produce identical ciphertexts, leaking information and enabling " +
			"pattern analysis attacks.",
		Severity:       "high",
		References:     []string{"CWE-1240", "CWE-329"},
		Recommendation: "Generate a random IV for every encryption operation using SecureRandom, and store or transmit it alongside the ciphertext.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && a.Name == "HardcodedIV"
		},
	})

	// -------------------------------------------------------------------------
	// CBOM-KS-001: Deprecated JKS Keystore Format
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:       "CBOM-KS-001",
		Category: "keystore",
		Title:    "Deprecated JKS Keystore Format",
		Description: "The Java KeyStore (JKS) format is a proprietary Sun Microsystems format " +
			"that was deprecated in Java 9 (JEP 229). It protects private keys with 3DES " +
			"and the integrity of the entire store with SHA-1 using a weak obfuscation scheme. " +
			"These cryptographic primitives are both deprecated by NIST SP 800-131A Rev 2.",
		Severity:   "medium",
		References: []string{"JEP 229", "NIST SP 800-131A Rev 2", "JDK-8044445"},
		Recommendation: "Migrate to PKCS12 format: KeyStore.getInstance(\"PKCS12\"). " +
			"In Java 9+ PKCS12 is the default. Convert existing JKS stores with: " +
			"keytool -importkeystore -srckeystore old.jks -destkeystore new.p12 -deststoretype PKCS12.",
		Match: func(node model.INode) bool {
			a, ok := node.(*model.Algorithm)
			return ok && strings.EqualFold(a.Name, "KeyStore-JKS")
		},
	})

	// ==========================================================================
	// NATIONAL CIPHER SUITES
	// Covers algorithms mandated by national standards bodies with limited
	// public review and restricted geographic scope. Per RFC 7696 §3.4, such
	// algorithms should be disabled by default and enabled only where required.
	// ==========================================================================

	// -------------------------------------------------------------------------
	// CBOM-NATIONAL-001: GOST (Russian national algorithms)
	// -------------------------------------------------------------------------
	registry.Register(&VulnRule{
		ID:       "CBOM-NATIONAL-001",
		Category: "national",
		Title:    "GOST — Russian National Cryptographic Algorithm",
		Description: "The GOST family (GOST R 34.10 signature, GOST R 34.11 hash, " +
			"GOST 28147-89 / Grasshopper block cipher) are Russian national standards " +
			"mandated by regulation in Russia. They have received limited independent " +
			"public cryptanalysis compared to NIST-approved algorithms, have restricted " +
			"geographic deployment, and their security properties are difficult to " +
			"verify externally. Per RFC 7696 §3.4, national cipher suites should be " +
			"disabled by default and enabled only where legally required.",
		Severity:   "low",
		References: []string{"RFC 7696 §3.4", "GOST R 34.10-2012", "GOST R 34.11-2012"},
		Recommendation: "Disable GOST algorithms unless required by regulatory mandate. " +
			"Where interoperability is not restricted, prefer NIST-approved equivalents: " +
			"SHA-256/SHA-3 (hash), ECDSA P-256 (signature), AES-256-GCM (encryption).",
		Match: func(node model.INode) bool {
			n, ok := node.(*model.Algorithm)
			if !ok {
				return false
			}
			upper := strings.ToUpper(n.Name)
			return strings.HasPrefix(upper, "GOST") ||
				upper == "GRASSHOPPER" ||
				upper == "STREEBOG" ||
				upper == "MAGMA"
		},
	})
}
