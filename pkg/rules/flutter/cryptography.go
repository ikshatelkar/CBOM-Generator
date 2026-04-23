package flutter

import (
	"regexp"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterFlutterDetectionRules registers all Flutter/Dart cryptography detection rules.
// Rules are grouped by library:
//   - package:crypto         — dart built-in: sha1, sha256, sha512, md5, Hmac
//   - package:cryptography   — modern Dart crypto (AesCbc, AesGcm, Ed25519, X25519, Ecdsa, etc.)
//   - package:pointycastle   — BouncyCastle port: BlockCipher, Digest, Mac, Signer, KeyGenerator
//   - package:encrypt        — high-level AES, RSA, Fernet wrapper
//   - dart:io                — TLS via SecureSocket / SecurityContext
func RegisterFlutterDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allFlutterRules() {
		registry.Register(r)
	}
}

func allFlutterRules() []*detection.Rule {
	return []*detection.Rule{
		// ── package:crypto ────────────────────────────────────────────────────
		dartCryptoDigest(),
		dartCryptoHmac(),
		// ── package:cryptography ──────────────────────────────────────────────
		dartCryptographyAES(),
		dartCryptographyChacha20(),
		dartCryptographyHashAlgorithm(),
		dartCryptographyHmac(),
		dartCryptographyEd25519(),
		dartCryptographyX25519(),
		dartCryptographyEcdh(),
		dartCryptographyEcdsa(),
		dartCryptographyRSA(),
		dartCryptographyKDF(),
		dartCryptographySecretBox(),
		// ── package:pointycastle ──────────────────────────────────────────────
		dartPointyCastleBlockCipher(),
		dartPaddedBlockCipher(),
		dartPointyCastleStreamCipher(),
		dartPointyCastleDigest(),
		dartPointyCastleMac(),
		dartPointyCastleKeyGenerator(),
		dartPointyCastleSigner(),
		dartPointyCastleAsymmetricKeyPairGenerator(),
		dartPointyCastleKDF(),
		// ── dart:math CSPRNG ─────────────────────────────────────────────────
		dartRandomSecure(),
		// ── JWT libraries (dart_jsonwebtoken, jose) ───────────────────────────
		dartJWTSign(),
		// ── package:encrypt ───────────────────────────────────────────────────
		dartEncryptAES(),
		dartEncryptRSA(),
		dartEncryptFernet(),
		// ── dart:io TLS ───────────────────────────────────────────────────────
		dartTLSSecureSocket(),
		dartTLSSecurityContext(),
		// ── isar database encryption (SQLCipher / AES-256) ───────────────────
		dartIsarEncryptionKey(),
		dartIsarChangeEncryptionKey(),
	}
}

// ============================================================================
// package:crypto
// ============================================================================

// dartCryptoDigest detects md5.convert(...), sha1.convert(...), sha256.convert(...), sha512.convert(...).
func dartCryptoDigest() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-crypto-digest",
		Language:  detection.LangDart,
		Bundle:    "DartCrypto",
		Pattern:   regexp.MustCompile(`\b(md5|sha1|sha224|sha256|sha384|sha512)\s*\.convert\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeDartHash(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// dartCryptoHmac detects Hmac(sha256, key).convert(...) — HMAC construction.
func dartCryptoHmac() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-crypto-hmac",
		Language:  detection.LangDart,
		Bundle:    "DartCrypto",
		Pattern:   regexp.MustCompile(`\bHmac\s*\(\s*(md5|sha1|sha224|sha256|sha384|sha512)\s*,`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			hash := normalizeDartHash(match[1])
			algo := model.NewAlgorithm("HMAC-"+hash, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// package:cryptography
// ============================================================================

// dartCryptographyAES detects AesCbc(), AesCtr(), AesGcm() constructors.
func dartCryptographyAES() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-aes",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\b(AesCbc|AesCtr|AesGcm)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := model.PrimitiveBlockCipher
			mode := ""
			switch name {
			case "AesGcm":
				prim = model.PrimitiveAEAD
				mode = "GCM"
			case "AesCbc":
				mode = "CBC"
			case "AesCtr":
				mode = "CTR"
			}
			algo := model.NewAlgorithm("AES", prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			if mode != "" {
				algo.Put(model.NewMode(mode))
			}
			return []model.INode{algo}
		},
	}
}

// dartCryptographyChacha20 detects Chacha20.poly1305Aead(), XChacha20.poly1305Aead().
func dartCryptographyChacha20() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-chacha20",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\b(X?Chacha20)\s*\.\s*poly1305Aead\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1]+"-Poly1305", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// dartCryptographyHashAlgorithm detects Sha1(), Sha224(), Sha256(), Sha384(), Sha512(), Blake2b(), Blake2s().
func dartCryptographyHashAlgorithm() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-hash",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\b(Sha1|Sha224|Sha256|Sha384|Sha512|Blake2b|Blake2s|Md5)\s*\(\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeDartCryptographyHash(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// dartCryptographyHmac detects Hmac.sha256(), Hmac.sha512(), etc.
func dartCryptographyHmac() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-hmac",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\bHmac\s*\.\s*(sha1|sha224|sha256|sha384|sha512)\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			hash := normalizeDartHash(match[1])
			algo := model.NewAlgorithm("HMAC-"+hash, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

func dartCryptographyEd25519() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-ed25519",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\bEd25519\s*\(\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

func dartCryptographyX25519() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-x25519",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\bX25519\s*\(\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X25519", model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// dartCryptographyEcdh detects Ecdh.p256(), Ecdh.p384(), Ecdh.p521().
func dartCryptographyEcdh() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-ecdh",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\bEcdh\s*\.\s*(p256|p384|p521)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			// p256 → P-256
			curve := strings.ToUpper(match[1][:1]) + "-" + match[1][1:]
			algo := model.NewAlgorithm("ECDH-"+curve, model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// dartCryptographyEcdsa detects Ecdsa.p256(Sha256()), Ecdsa.p384(Sha384()), etc.
func dartCryptographyEcdsa() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-ecdsa",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\bEcdsa\s*\.\s*(p256|p384|p521)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			curve := strings.ToUpper(match[1][:1]) + "-" + match[1][1:]
			algo := model.NewAlgorithm("ECDSA-"+curve, model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// dartCryptographyRSA detects RsaPss(), RsaSsaPkcs1v15().
func dartCryptographyRSA() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-rsa",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\b(RsaPss|RsaSsaPkcs1v15)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// dartCryptographyKDF detects Pbkdf2(...), Hkdf(...), Argon2id(...).
func dartCryptographyKDF() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-kdf",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\b(Pbkdf2|Hkdf|Argon2id)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := model.PrimitiveKeyDerivation
			if name == "Pbkdf2" || name == "Argon2id" {
				prim = model.PrimitivePasswordHash
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// dartCryptographySecretBox detects SecretBox symmetric authenticated encryption.
func dartCryptographySecretBox() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-cryptography-secretbox",
		Language:  detection.LangDart,
		Bundle:    "DartCryptography",
		Pattern:   regexp.MustCompile(`\bSecretBox\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SecretBox", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// package:pointycastle (BouncyCastle port for Dart)
// ============================================================================

// dartPointyCastleBlockCipher detects BlockCipher('AES/CBC'), BlockCipher('AES/GCM'), etc.
func dartPointyCastleBlockCipher() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-blockcipher",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\bBlockCipher\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			raw := match[1] // e.g. "AES/CBC", "DES-EDE3/CBC"
			parts := strings.Split(raw, "/")
			algoName := normalizeDartPointyCastleAlgoName(parts[0])
			prim := classifyDartCipherPrimitive(raw)
			algo := model.NewAlgorithm(algoName, prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			if len(parts) > 1 && parts[1] != "" {
				algo.Put(model.NewMode(parts[1]))
			}
			if len(parts) > 2 && parts[2] != "" && !strings.EqualFold(parts[2], "NoPadding") {
				algo.Put(model.NewPadding(parts[2]))
			}
			return []model.INode{algo}
		},
	}
}

// dartPointyCastleDigest detects Digest('SHA-256'), Digest('MD5'), etc.
func dartPointyCastleDigest() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-digest",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\bDigest\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := model.PrimitiveHash
			if strings.Contains(strings.ToUpper(name), "SHAKE") {
				prim = model.PrimitiveXOF
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// dartPointyCastleMac detects Mac('SHA-256/HMAC'), Mac('AES/CMAC'), etc.
func dartPointyCastleMac() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-mac",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\bMac\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// dartPointyCastleKeyGenerator detects KeyGenerator('AES'), KeyGenerator('RSA'), etc.
func dartPointyCastleKeyGenerator() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-keygen",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\bKeyGenerator\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := classifyDartCipherPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyGen)
			key := model.NewKey(name, model.KindSecretKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// dartPointyCastleSigner detects Signer('RSA'), Signer('ECDSA'), etc.
func dartPointyCastleSigner() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-signer",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\bSigner\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// dartPointyCastleAsymmetricKeyPairGenerator detects AsymmetricKeyPairGenerator('RSA').
func dartPointyCastleAsymmetricKeyPairGenerator() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-asymmetric-keypairgen",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`AsymmetricKeyPairGenerator\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := classifyDartAsymmetricPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyGen)
			pubKey := model.NewKey(name, model.KindPublicKey, loc)
			pubKey.Put(algo)
			privKey := model.NewKey(name, model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{pubKey, privKey}
		},
	}
}

// dartPointyCastleKDF detects PBKDF2KeyDerivator, Scrypt, etc.
func dartPointyCastleKDF() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-kdf",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\b(PBKDF2KeyDerivator|ScryptParameters|HkdfParameters)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			nameMap := map[string]string{
				"PBKDF2KeyDerivator": "PBKDF2",
				"ScryptParameters":   "scrypt",
				"HkdfParameters":     "HKDF",
			}
			name, ok := nameMap[match[1]]
			if !ok {
				name = match[1]
			}
			prim := model.PrimitiveKeyDerivation
			if name == "PBKDF2" || name == "scrypt" {
				prim = model.PrimitivePasswordHash
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// package:encrypt
// ============================================================================

// dartEncryptAES detects AES(key) or AES(key, mode: AESMode.cbc).
func dartEncryptAES() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-encrypt-aes",
		Language:  detection.LangDart,
		Bundle:    "DartEncrypt",
		Pattern:   regexp.MustCompile(`\bAES\s*\([^)]*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			modeMatch := regexp.MustCompile(`AESMode\s*\.\s*(\w+)`).FindStringSubmatch(match[0])
			if len(modeMatch) >= 2 {
				algo.Put(model.NewMode(strings.ToUpper(modeMatch[1])))
			}
			return []model.INode{algo}
		},
	}
}

// dartEncryptRSA detects RSA(publicKey: key) from package:encrypt.
func dartEncryptRSA() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-encrypt-rsa",
		Language:  detection.LangDart,
		Bundle:    "DartEncrypt",
		Pattern:   regexp.MustCompile(`\bRSA\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// dartEncryptFernet detects Fernet(key) — wraps AES-128-CBC + HMAC-SHA256.
func dartEncryptFernet() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-encrypt-fernet",
		Language:  detection.LangDart,
		Bundle:    "DartEncrypt",
		Pattern:   regexp.MustCompile(`\bFernet\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Fernet", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// dart:io TLS
// ============================================================================

// dartTLSSecureSocket detects RawSecureSocket.connect(...), SecureSocket.connect(...), etc.
func dartTLSSecureSocket() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-tls-securesocket",
		Language:  detection.LangDart,
		Bundle:    "DartTLS",
		Pattern:   regexp.MustCompile(`(?:RawSecureSocket|SecureSocket|SecureServerSocket)\s*\.\s*(?:connect|bind|secure)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

// dartTLSSecurityContext detects SecurityContext() or SecurityContext.defaultContext.
func dartTLSSecurityContext() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-tls-securitycontext",
		Language:  detection.LangDart,
		Bundle:    "DartTLS",
		Pattern:   regexp.MustCompile(`SecurityContext\s*(?:\.\s*defaultContext|\s*\()`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func normalizeDartHash(name string) string {
	switch strings.ToLower(name) {
	case "md5":
		return "MD5"
	case "sha1":
		return "SHA-1"
	case "sha224":
		return "SHA-224"
	case "sha256":
		return "SHA-256"
	case "sha384":
		return "SHA-384"
	case "sha512":
		return "SHA-512"
	default:
		return strings.ToUpper(name)
	}
}

func normalizeDartCryptographyHash(name string) string {
	switch name {
	case "Sha1":
		return "SHA-1"
	case "Sha224":
		return "SHA-224"
	case "Sha256":
		return "SHA-256"
	case "Sha384":
		return "SHA-384"
	case "Sha512":
		return "SHA-512"
	case "Blake2b":
		return "BLAKE2b"
	case "Blake2s":
		return "BLAKE2s"
	case "Md5":
		return "MD5"
	default:
		return name
	}
}

func classifyDartCipherPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "GCM") || strings.Contains(upper, "CCM") ||
		strings.Contains(upper, "EAX") || strings.Contains(upper, "OCB"):
		return model.PrimitiveAEAD
	case strings.Contains(upper, "CHACHA") && strings.Contains(upper, "POLY"):
		return model.PrimitiveAEAD
	case strings.Contains(upper, "AES"), strings.Contains(upper, "DES"),
		strings.Contains(upper, "BLOWFISH"), strings.Contains(upper, "CAMELLIA"),
		strings.Contains(upper, "TWOFISH"), strings.Contains(upper, "SERPENT"),
		strings.Contains(upper, "CAST"), strings.Contains(upper, "SEED"):
		return model.PrimitiveBlockCipher
	case strings.Contains(upper, "RC4"), strings.Contains(upper, "CHACHA"),
		strings.Contains(upper, "SALSA"):
		return model.PrimitiveStreamCipher
	default:
		return model.PrimitiveUnknown
	}
}

func classifyDartAsymmetricPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "RSA"):
		return model.PrimitivePublicKeyEncryption
	case strings.Contains(upper, "ECDSA"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "DSA"), strings.Contains(upper, "EC"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "DH"), strings.Contains(upper, "ECDH"):
		return model.PrimitiveKeyAgreement
	default:
		return model.PrimitiveUnknown
	}
}

// normalizeDartPointyCastleAlgoName converts PointyCastle algorithm name prefixes
// to canonical names that match the vulnerability database.
func normalizeDartPointyCastleAlgoName(raw string) string {
	upper := strings.ToUpper(raw)
	switch {
	case upper == "DES-EDE3" || upper == "DESEDE3" || upper == "3DES" || upper == "TDEA":
		return "3DES"
	case upper == "DES-EDE" || upper == "DESEDE":
		return "3DES"
	case upper == "BLOWFISH" || upper == "BF":
		return "Blowfish"
	default:
		return raw
	}
}

// ============================================================================
// package:pointycastle — PaddedBlockCipher / StreamCipher
// ============================================================================

// dartPaddedBlockCipher detects PaddedBlockCipher('AES/CBC/PKCS7', ...) in PointyCastle.
func dartPaddedBlockCipher() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-paddedblockcipher",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\bPaddedBlockCipher\s*\(\s*['"]([^'"]+)['"]\s*[,)]`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			raw := match[1]
			parts := strings.Split(raw, "/")
			algoName := normalizeDartPointyCastleAlgoName(parts[0])
			prim := classifyDartCipherPrimitive(raw)
			algo := model.NewAlgorithm(algoName, prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			if len(parts) > 1 && parts[1] != "" {
				algo.Put(model.NewMode(parts[1]))
			}
			if len(parts) > 2 && parts[2] != "" && !strings.EqualFold(parts[2], "NoPadding") {
				algo.Put(model.NewPadding(parts[2]))
			}
			return []model.INode{algo}
		},
	}
}

// dartPointyCastleStreamCipher detects StreamCipher('RC4', ...) in PointyCastle.
func dartPointyCastleStreamCipher() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-pointycastle-streamcipher",
		Language:  detection.LangDart,
		Bundle:    "PointyCastle",
		Pattern:   regexp.MustCompile(`\bStreamCipher\s*\(\s*['"]([^'"]+)['"]\s*[,)]`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeDartPointyCastleAlgoName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveStreamCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// dart:math — Random.secure() CSPRNG
// ============================================================================

// dartRandomSecure detects Random.secure() calls (Dart's CSPRNG).
func dartRandomSecure() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-random-secure",
		Language:  detection.LangDart,
		Bundle:    "DartCore",
		Pattern:   regexp.MustCompile(`\bRandom\s*\.\s*secure\s*\(\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Random.secure", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// dart_jsonwebtoken / jose JWT libraries
// ============================================================================

// dartJWTSign detects JWT token signing: JWT.sign(payload, SecretKey('...', algorithm: JWTAlgorithm.HS256))
// or JWTBuilder with algorithm specification.
func dartJWTSign() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-jwt-sign",
		Language:  detection.LangDart,
		Bundle:    "DartJWT",
		Pattern:   regexp.MustCompile(`\bJWT(?:Algorithm)?\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|EdDSA|NONE|none)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := classifyDartJWTPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// isar database encryption (SQLCipher)
// ============================================================================

// dartIsarEncryptionKey detects Isar.open(encryptionKey: ...) and
// Isar.openAsync(encryptionKey: ...) — signals SQLCipher AES-256 DB encryption.
func dartIsarEncryptionKey() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-isar-encryption-key",
		Language:  detection.LangDart,
		Bundle:    "DartIsar",
		Pattern:   regexp.MustCompile(`\bencryptionKey\s*:`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES-256", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// dartIsarChangeEncryptionKey detects isar.changeEncryptionKey(...) — SQLCipher key rotation.
func dartIsarChangeEncryptionKey() *detection.Rule {
	return &detection.Rule{
		ID:        "dart-isar-change-encryption-key",
		Language:  detection.LangDart,
		Bundle:    "DartIsar",
		Pattern:   regexp.MustCompile(`\.changeEncryptionKey\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES-256", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func classifyDartJWTPrimitive(alg string) model.Primitive {
	upper := strings.ToUpper(alg)
	switch {
	case strings.HasPrefix(upper, "HS"):
		return model.PrimitiveMAC
	case strings.HasPrefix(upper, "RS"), strings.HasPrefix(upper, "PS"):
		return model.PrimitiveSignature
	case strings.HasPrefix(upper, "ES"), upper == "EDDSA":
		return model.PrimitiveSignature
	case upper == "NONE":
		// "none" disables signing — treated as MAC so CBOM-JWT-001 fires.
		return model.PrimitiveMAC
	default:
		return model.PrimitiveUnknown
	}
}
