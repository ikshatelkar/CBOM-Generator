package rust

import (
	"regexp"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterRustDetectionRules registers all Rust cryptography detection rules.
// Rules are grouped by crate:
//   - ring           — most common production Rust crypto library
//   - RustCrypto     — aes-gcm, chacha20poly1305, sha2, sha3, hmac, rsa, ed25519-dalek, x25519-dalek
//   - argon2 / bcrypt / scrypt / pbkdf2
//   - rustls         — TLS
//   - jsonwebtoken   — JWT
func RegisterRustDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allRustRules() {
		registry.Register(r)
	}
}

func allRustRules() []*detection.Rule {
	return []*detection.Rule{
		// ── ring crate ────────────────────────────────────────────────────────
		rustRingAEAD(),
		rustRingDigest(),
		rustRingHMAC(),
		rustRingSignature(),
		rustRingPBKDF2(),
		rustRingRandom(),
		// ── RustCrypto: AEAD (aes-gcm / chacha20poly1305) ────────────────────
		rustAesGcm(),
		rustChaCha20Poly1305(),
		rustAesSiv(),
		// ── RustCrypto: symmetric ciphers ────────────────────────────────────
		rustAesCBC(),
		rustAesCTR(),
		// ── RustCrypto: hash crates ───────────────────────────────────────────
		rustSha2(),
		rustSha3(),
		rustMD5(),
		rustBlake2(),
		rustBlake3(),
		// ── RustCrypto: HMAC ─────────────────────────────────────────────────
		rustHmac(),
		// ── RustCrypto: RSA ───────────────────────────────────────────────────
		rustRSAPrivateKey(),
		rustRSASign(),
		// ── RustCrypto: ed25519-dalek ─────────────────────────────────────────
		rustEd25519SigningKey(),
		rustEd25519Verifying(),
		// ── RustCrypto: x25519-dalek ──────────────────────────────────────────
		rustX25519(),
		// ── RustCrypto: p256 / p384 ───────────────────────────────────────────
		rustECDSA(),
		// ── Password hashing ─────────────────────────────────────────────────
		rustArgon2(),
		rustBcrypt(),
		rustScrypt(),
		rustPBKDF2Standalone(),
		// ── rustls ───────────────────────────────────────────────────────────
		rustTLSClientConfig(),
		rustTLSServerConfig(),
		rustTLSClientConfigWithProvider(),
		rustTLSServerConfigWithProvider(),
		// ── rustls: TLS cipher suite constants ───────────────────────────────
		rustTLSCipherSuite(),
		// ── rustls: signature scheme constants ───────────────────────────────
		rustSignatureScheme(),
		// ── rustls / ring: SM4 cipher ─────────────────────────────────────────
		rustSM4(),
		// ── HKDF (hkdf crate) ────────────────────────────────────────────────
		rustHKDF(),
		// ── jsonwebtoken ─────────────────────────────────────────────────────
		rustJWTEncode(),
		rustJWTDecode(),
		rustJWTAlgorithm(),
		// ── SQLCipher (database-level AES-256 encryption) ────────────────────
		rustSQLCipherPragmaKey(),
	}
}

// ============================================================================
// ring crate
// ============================================================================

// rustRingAEAD detects ring::aead::LessSafeKey::new, UnboundKey::new with AES_256_GCM etc.
func rustRingAEAD() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ring-aead",
		Language:  detection.LangRust,
		Bundle:    "RustRing",
		Pattern:   regexp.MustCompile(`\b(AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := normalizeRingAEAD(match[1])
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// rustRingDigest detects ring::digest::digest(&SHA256, ...) or digest::SHA256 references.
func rustRingDigest() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ring-digest",
		Language:  detection.LangRust,
		Bundle:    "RustRing",
		Pattern:   regexp.MustCompile(`\b(?:digest\s*::\s*)?(SHA1_FOR_LEGACY_USE_ONLY|SHA256|SHA384|SHA512|SHA512_256)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRingDigest(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// rustRingHMAC detects hmac::Key::new(HMAC_SHA256, ...) or HMAC_SHA256/HMAC_SHA384/HMAC_SHA512 refs.
func rustRingHMAC() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ring-hmac",
		Language:  detection.LangRust,
		Bundle:    "RustRing",
		Pattern:   regexp.MustCompile(`\b(HMAC_SHA256|HMAC_SHA384|HMAC_SHA512)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := "HMAC-" + strings.TrimPrefix(match[1], "HMAC_")
			name = strings.ReplaceAll(name, "_", "-")
			algo := model.NewAlgorithm(name, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// rustRingSignature detects EcdsaKeyPair::from_pkcs8, Ed25519KeyPair::from_pkcs8, etc.
func rustRingSignature() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ring-signature",
		Language:  detection.LangRust,
		Bundle:    "RustRing",
		Pattern:   regexp.MustCompile(`\b(EcdsaKeyPair|Ed25519KeyPair|RsaKeyPair)\s*::\s*(?:from_pkcs8|generate_pkcs8|from_der)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := normalizeRingKeyPairType(match[1])
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			privKey := model.NewKey(name, model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// rustRingPBKDF2 detects pbkdf2::derive(PBKDF2_HMAC_SHA256, iterations, ...).
func rustRingPBKDF2() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ring-pbkdf2",
		Language:  detection.LangRust,
		Bundle:    "RustRing",
		Pattern:   regexp.MustCompile(`pbkdf2\s*::\s*derive\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PBKDF2", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// rustRingRandom detects SystemRandom::new() — ring's CSPRNG.
func rustRingRandom() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ring-random",
		Language:  detection.LangRust,
		Bundle:    "RustRing",
		Pattern:   regexp.MustCompile(`SystemRandom\s*::\s*new\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SystemRandom", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// RustCrypto: AEAD crates
// ============================================================================

// rustAesGcm detects Aes256Gcm::new(key), Aes128Gcm::new(key).
func rustAesGcm() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-aes-gcm",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(Aes128Gcm|Aes256Gcm|Aes128SivAead|Aes256SivAead)\s*::\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRustAESName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("GCM"))
			return []model.INode{algo}
		},
	}
}

func rustChaCha20Poly1305() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-chacha20poly1305",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(ChaCha20Poly1305|XChaCha20Poly1305)\s*::\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			if name == "XChaCha20Poly1305" {
				name = "XChaCha20-Poly1305"
			} else {
				name = "ChaCha20-Poly1305"
			}
			algo := model.NewAlgorithm(name, model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func rustAesSiv() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-aes-siv",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(Aes128SivAead|Aes256SivAead|Aes128Siv|Aes256Siv)\s*::\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("AES-SIV", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// RustCrypto: block cipher modes (aes + cbc-mode / ctr-mode)
// ============================================================================

func rustAesCBC() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-aes-cbc",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(Aes128|Aes256)\s*,\s*(?:cbc|Cbc|CBC)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRustAESName(match[1]) + "-CBC"
			algo := model.NewAlgorithm(name, model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("CBC"))
			return []model.INode{algo}
		},
	}
}

func rustAesCTR() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-aes-ctr",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(Aes128|Aes256)\s*,\s*(?:ctr|Ctr|CTR)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRustAESName(match[1]) + "-CTR"
			algo := model.NewAlgorithm(name, model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("CTR"))
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// RustCrypto: hash crates
// ============================================================================

// rustSha2 detects Sha256::new(), Sha512::new(), Sha384::new() from sha2 crate.
func rustSha2() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-sha2",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(Sha224|Sha256|Sha384|Sha512|Sha512_256|Sha512_224)\s*::\s*new\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRustHashName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// rustSha3 detects Sha3_256::new(), Sha3_512::new(), Keccak256::new() from sha3 crate.
func rustSha3() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-sha3",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(Sha3_224|Sha3_256|Sha3_384|Sha3_512|Keccak256|Keccak512|Shake128|Shake256)\s*::\s*new\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRustSha3Name(match[1])
			prim := model.PrimitiveHash
			if strings.HasPrefix(strings.ToUpper(match[1]), "SHAKE") {
				prim = model.PrimitiveXOF
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func rustMD5() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-md5",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\bMd5\s*::\s*new\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("MD5", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func rustBlake2() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-blake2",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(Blake2b512|Blake2s256|Blake2b|Blake2s)\s*::\s*new\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRustBlakeName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func rustBlake3() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-blake3",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\bblake3\s*::\s*(?:hash|Hasher)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("BLAKE3", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// RustCrypto: HMAC
// ============================================================================

// rustHmac detects Hmac::<Sha256>::new_from_slice(key) from hmac crate.
func rustHmac() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-hmac",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`Hmac\s*::\s*<\s*(Sha\w+|Md5)\s*>\s*::\s*(?:new_from_slice|new)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			hash := normalizeRustHashName(match[1])
			algo := model.NewAlgorithm("HMAC-"+hash, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// RustCrypto: RSA
// ============================================================================

// rustRSAPrivateKey detects RsaPrivateKey::new(&mut rng, 2048).
func rustRSAPrivateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rsa-privatekey",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`RsaPrivateKey\s*::\s*new\s*\([^,]+,\s*(\d+)\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			if len(match) >= 2 {
				if bits := parseRustInt(match[1]); bits > 0 {
					algo.Put(model.NewKeyLength(bits))
				}
			}
			privKey := model.NewKey("RSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			pubKey := model.NewKey("RSA", model.KindPublicKey, loc)
			pubKey.Put(algo)
			return []model.INode{privKey, pubKey}
		},
	}
}

// rustRSASign detects pkcs1v15::SigningKey::new(key) or pss::SigningKey::new(key).
func rustRSASign() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rsa-sign",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`(?:pkcs1v15|pss)\s*::\s*SigningKey\s*::\s*(?:new|random)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			scheme := "RSA-PKCS1v15"
			if strings.Contains(match[0], "pss") {
				scheme = "RSA-PSS"
			}
			algo := model.NewAlgorithm(scheme, model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// RustCrypto: ed25519-dalek
// ============================================================================

// rustEd25519SigningKey detects SigningKey::generate(&mut rng) from ed25519-dalek.
func rustEd25519SigningKey() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ed25519-signingkey",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\bSigningKey\s*::\s*(?:generate|from_bytes|from)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey("Ed25519", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

func rustEd25519Verifying() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ed25519-verifyingkey",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\bVerifyingKey\s*::\s*(?:from|from_bytes)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			pubKey := model.NewKey("Ed25519", model.KindPublicKey, loc)
			pubKey.Put(algo)
			return []model.INode{pubKey}
		},
	}
}

// ============================================================================
// RustCrypto: x25519-dalek
// ============================================================================

func rustX25519() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-x25519",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(?:EphemeralSecret|StaticSecret)\s*::\s*(?:random_from_rng|new|random)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X25519", model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// RustCrypto: ECDSA (p256 / p384)
// ============================================================================

func rustECDSA() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-ecdsa",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(?:ecdsa\s*::\s*)?SigningKey\s*::\s*<\s*(p256|p384|NistP256|NistP384)\s*>`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			curve := "P-256"
			if len(match) >= 2 && (match[1] == "p384" || match[1] == "NistP384") {
				curve = "P-384"
			}
			algo := model.NewAlgorithm("ECDSA-"+curve, model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Password hashing crates
// ============================================================================

// rustArgon2 detects Argon2::default().hash_password(...) or Argon2::new(Algorithm::Argon2id, ...).
func rustArgon2() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-argon2",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(?:Argon2\s*::\s*(?:default|new|id|i|d)\s*\(|argon2\s*::\s*hash_encoded|argon2\s*::\s*verify_encoded)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "Argon2"
			if strings.Contains(match[0], "::id") || strings.Contains(match[0], "Argon2id") {
				name = "Argon2id"
			} else if strings.Contains(match[0], "::i") {
				name = "Argon2i"
			}
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func rustBcrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-bcrypt",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\bbcrypt\s*::\s*(?:hash|verify)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func rustScrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-scrypt",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\bscrypt\s*::\s*(?:scrypt|Params)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("scrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func rustPBKDF2Standalone() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-pbkdf2",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\bpbkdf2\s*::\s*(?:pbkdf2_hmac|pbkdf2)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PBKDF2", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// rustls
// ============================================================================

func rustTLSClientConfig() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rustls-client",
		Language:  detection.LangRust,
		Bundle:    "Rustls",
		Pattern:   regexp.MustCompile(`ClientConfig\s*::\s*builder\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

func rustTLSServerConfig() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rustls-server",
		Language:  detection.LangRust,
		Bundle:    "Rustls",
		Pattern:   regexp.MustCompile(`ServerConfig\s*::\s*builder\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

// ============================================================================
// rustls: builder_with_provider variants
// ============================================================================

// rustTLSClientConfigWithProvider detects ClientConfig::builder_with_provider(provider).
func rustTLSClientConfigWithProvider() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rustls-client-with-provider",
		Language:  detection.LangRust,
		Bundle:    "Rustls",
		Pattern:   regexp.MustCompile(`ClientConfig\s*::\s*builder_with_provider\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

// rustTLSServerConfigWithProvider detects ServerConfig::builder_with_provider(provider).
func rustTLSServerConfigWithProvider() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rustls-server-with-provider",
		Language:  detection.LangRust,
		Bundle:    "Rustls",
		Pattern:   regexp.MustCompile(`ServerConfig\s*::\s*builder_with_provider\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

// ============================================================================
// rustls: TLS cipher suite constants
// Detects: CipherSuite::TLS_AES_256_GCM_SHA384, CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
//          CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, etc.
// ============================================================================

func rustTLSCipherSuite() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rustls-ciphersuite",
		Language:  detection.LangRust,
		Bundle:    "Rustls",
		Pattern:   regexp.MustCompile(`CipherSuite\s*::\s*(TLS_\w+)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := normalizeRustlsCipherSuite(match[1])
			suite := model.NewCipherSuite(name, loc)
			_ = prim
			return []model.INode{suite}
		},
	}
}

// ============================================================================
// rustls: SignatureScheme constants
// Detects: SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::RSA_PSS_SHA256,
//          SignatureScheme::ED25519, etc.
// ============================================================================

func rustSignatureScheme() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-rustls-sigscheme",
		Language:  detection.LangRust,
		Bundle:    "Rustls",
		Pattern:   regexp.MustCompile(`SignatureScheme\s*::\s*(ECDSA_\w+|RSA_\w+|ED25519|ED448)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := normalizeRustSignatureScheme(match[1])
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// SM4 cipher (Chinese national standard — rustls ConnectionTrafficSecrets)
// Detects: ConnectionTrafficSecrets::Sm4Gcm, ConnectionTrafficSecrets::Sm4Ccm,
//          Sm4::new(), sm4 crate usage.
// ============================================================================

func rustSM4() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-sm4",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(?:Sm4(?:Gcm|Ccm)?|SM4)\s*(?:::\s*new\s*\(|[{])`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			prim := model.PrimitiveAEAD
			mode := "GCM"
			if strings.Contains(match[0], "Ccm") || strings.Contains(match[0], "CCM") {
				mode = "CCM"
			}
			algo := model.NewAlgorithm("SM4", prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode(mode))
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// HKDF (hkdf crate)
// Detects: Hkdf::<Sha256>::new(salt, ikm), hkdf::Hkdf::<Sha512>::new(...)
// ============================================================================

func rustHKDF() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-hkdf",
		Language:  detection.LangRust,
		Bundle:    "RustCrypto",
		Pattern:   regexp.MustCompile(`\b(?:hkdf\s*::\s*)?Hkdf\s*::\s*<\s*(\w+)\s*>\s*::\s*(?:new|extract)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			hash := "SHA-256"
			if len(match) >= 2 {
				hash = normalizeRustHashName(match[1])
			}
			algo := model.NewAlgorithm("HKDF-"+hash, model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// jsonwebtoken crate
// ============================================================================

// rustJWTEncode detects encode(&Header::new(Algorithm::HS256), &claims, &key).
func rustJWTEncode() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-jwt-encode",
		Language:  detection.LangRust,
		Bundle:    "RustJWT",
		Pattern:   regexp.MustCompile(`\bjsonwebtoken\s*::\s*encode\s*\(|(?:^|[^:])encode\s*\(\s*&Header`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("JWT", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func rustJWTDecode() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-jwt-decode",
		Language:  detection.LangRust,
		Bundle:    "RustJWT",
		Pattern:   regexp.MustCompile(`\bjsonwebtoken\s*::\s*decode\s*\(|(?:^|[^:])decode\s*::\s*<\w+>\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("JWT", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// rustJWTAlgorithm detects Algorithm::HS256, Algorithm::RS256, etc. in jsonwebtoken.
func rustJWTAlgorithm() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-jwt-algorithm",
		Language:  detection.LangRust,
		Bundle:    "RustJWT",
		Pattern:   regexp.MustCompile(`Algorithm\s*::\s*(HS256|HS384|HS512|RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|EdDSA)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := rustJWTAlgorithmPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func normalizeRingAEAD(name string) (string, model.Primitive) {
	switch name {
	case "AES_128_GCM":
		return "AES-128-GCM", model.PrimitiveAEAD
	case "AES_256_GCM":
		return "AES-256-GCM", model.PrimitiveAEAD
	case "CHACHA20_POLY1305":
		return "ChaCha20-Poly1305", model.PrimitiveAEAD
	default:
		return name, model.PrimitiveAEAD
	}
}

func normalizeRingDigest(name string) string {
	switch name {
	case "SHA1_FOR_LEGACY_USE_ONLY":
		return "SHA-1"
	case "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	case "SHA512_256":
		return "SHA-512/256"
	default:
		return name
	}
}

func normalizeRingKeyPairType(name string) (string, model.Primitive) {
	switch name {
	case "EcdsaKeyPair":
		return "ECDSA", model.PrimitiveSignature
	case "Ed25519KeyPair":
		return "Ed25519", model.PrimitiveSignature
	case "RsaKeyPair":
		return "RSA", model.PrimitivePublicKeyEncryption
	default:
		return name, model.PrimitiveSignature
	}
}

func normalizeRustAESName(name string) string {
	switch name {
	case "Aes128Gcm", "Aes128":
		return "AES-128"
	case "Aes256Gcm", "Aes256":
		return "AES-256"
	default:
		return strings.ReplaceAll(name, "Aes", "AES-")
	}
}

func normalizeRustHashName(name string) string {
	switch name {
	case "Sha224":
		return "SHA-224"
	case "Sha256":
		return "SHA-256"
	case "Sha384":
		return "SHA-384"
	case "Sha512":
		return "SHA-512"
	case "Sha512_256":
		return "SHA-512/256"
	case "Sha512_224":
		return "SHA-512/224"
	case "Md5":
		return "MD5"
	default:
		return name
	}
}

func normalizeRustSha3Name(name string) string {
	switch name {
	case "Sha3_224":
		return "SHA3-224"
	case "Sha3_256":
		return "SHA3-256"
	case "Sha3_384":
		return "SHA3-384"
	case "Sha3_512":
		return "SHA3-512"
	case "Keccak256":
		return "Keccak-256"
	case "Keccak512":
		return "Keccak-512"
	case "Shake128":
		return "SHAKE-128"
	case "Shake256":
		return "SHAKE-256"
	default:
		return name
	}
}

func normalizeRustBlakeName(name string) string {
	switch name {
	case "Blake2b512", "Blake2b":
		return "BLAKE2b-512"
	case "Blake2s256", "Blake2s":
		return "BLAKE2s-256"
	default:
		return name
	}
}

func rustJWTAlgorithmPrimitive(alg string) model.Primitive {
	upper := strings.ToUpper(alg)
	switch {
	case strings.HasPrefix(upper, "HS"):
		return model.PrimitiveMAC
	case strings.HasPrefix(upper, "RS"), strings.HasPrefix(upper, "PS"),
		strings.HasPrefix(upper, "ES"), upper == "EDDSA":
		return model.PrimitiveSignature
	case upper == "NONE":
		// "none" disables signing — treated as MAC so CBOM-JWT-001 fires.
		return model.PrimitiveMAC
	default:
		return model.PrimitiveUnknown
	}
}

// ============================================================================
// SQLCipher — database-level AES-256 encryption
// ============================================================================

// rustSQLCipherPragmaKey detects SQLCipher's PRAGMA key / PRAGMA rekey calls
// embedded in Rust string literals (e.g. isar_core's sqlite3.rs).
func rustSQLCipherPragmaKey() *detection.Rule {
	return &detection.Rule{
		ID:        "rust-sqlcipher-pragma-key",
		Language:  detection.LangRust,
		Bundle:    "RustSQLCipher",
		Pattern:   regexp.MustCompile(`"PRAGMA\s+(?:re)?key\s*=`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES-256", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// normalizeRustlsCipherSuite maps a TLS CipherSuite constant name to a display name and primitive.
func normalizeRustlsCipherSuite(name string) (string, model.Primitive) {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "AES_128_GCM"):
		return "TLS_AES_128_GCM", model.PrimitiveAEAD
	case strings.Contains(upper, "AES_256_GCM"):
		return "TLS_AES_256_GCM", model.PrimitiveAEAD
	case strings.Contains(upper, "CHACHA20_POLY1305"):
		return "TLS_CHACHA20_POLY1305", model.PrimitiveAEAD
	case strings.Contains(upper, "AES_128_CCM"):
		return "TLS_AES_128_CCM", model.PrimitiveAEAD
	case strings.Contains(upper, "SM4_GCM"):
		return "TLS_SM4_GCM", model.PrimitiveAEAD
	case strings.Contains(upper, "SM4_CCM"):
		return "TLS_SM4_CCM", model.PrimitiveAEAD
	default:
		return name, model.PrimitiveUnknown
	}
}

// normalizeRustSignatureScheme maps a SignatureScheme constant to a display name and primitive.
func normalizeRustSignatureScheme(name string) (string, model.Primitive) {
	upper := strings.ToUpper(name)
	switch {
	case upper == "ED25519":
		return "Ed25519", model.PrimitiveSignature
	case upper == "ED448":
		return "Ed448", model.PrimitiveSignature
	case strings.Contains(upper, "ECDSA_NISTP256"):
		return "ECDSA-P256", model.PrimitiveSignature
	case strings.Contains(upper, "ECDSA_NISTP384"):
		return "ECDSA-P384", model.PrimitiveSignature
	case strings.Contains(upper, "ECDSA_NISTP521"):
		return "ECDSA-P521", model.PrimitiveSignature
	case strings.Contains(upper, "RSA_PSS_SHA256"):
		return "RSA-PSS-SHA256", model.PrimitiveSignature
	case strings.Contains(upper, "RSA_PSS_SHA384"):
		return "RSA-PSS-SHA384", model.PrimitiveSignature
	case strings.Contains(upper, "RSA_PSS_SHA512"):
		return "RSA-PSS-SHA512", model.PrimitiveSignature
	case strings.Contains(upper, "RSA_PKCS1_SHA256"):
		return "RSA-PKCS1-SHA256", model.PrimitiveSignature
	case strings.Contains(upper, "RSA_PKCS1_SHA384"):
		return "RSA-PKCS1-SHA384", model.PrimitiveSignature
	case strings.Contains(upper, "RSA_PKCS1_SHA512"):
		return "RSA-PKCS1-SHA512", model.PrimitiveSignature
	default:
		return name, model.PrimitiveSignature
	}
}

func parseRustInt(s string) int {
	s = strings.TrimSpace(s)
	val := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		val = val*10 + int(c-'0')
	}
	return val
}
