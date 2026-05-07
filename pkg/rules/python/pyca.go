package python

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterAllPythonDetectionRules registers every Python crypto detection rule.
// Rules are grouped by library:
//   - pyca/cryptography  — the primary modern Python crypto library
//   - Python stdlib       — hashlib, hmac, random
//   - PyCryptodome        — Crypto.* (maintained PyCrypto fork)
//   - PyNaCl             — libsodium bindings
//   - PyJWT              — JSON Web Token library
func RegisterAllPythonDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allPythonRules() {
		registry.Register(r)
	}
}

func allPythonRules() []*detection.Rule {
	return []*detection.Rule{
		// ── pyca/cryptography ────────────────────────────────────────────────
		pycaSymmetricAlgorithm(),
		pycaCipherMode(),
		pycaAEADCipher(),
		pycaHashAlgorithm(),
		pycaHMAC(),
		pycaCMAC(),
		pycaRSAKeyGen(),
		pycaECKeyGen(),
		pycaDSAKeyGen(),
		pycaDHKeyGen(),
		pycaEd25519(),
		pycaEd448(),
		pycaX25519(),
		pycaX448(),
		pycaKDF(),
		pycaFernet(),
		pycaRSASign(),
		pycaECSign(),
		pycaRSAEncrypt(),
		pycaCipherSuite(),
		pycaSSLContext(),
		pycaOsUrandom(),
		pycaSecrets(),
		pycaBlake3(),
		oqsKeyEncapsulation(),
		oqsSignature(),
		pycaMLDSA(),
		pycaMLKEM(),
		pycaArgon2(),
		pycaPoly1305(),
		pycaECDHExchange(),
		pycaBcrypt(),
		pycaRSADecrypt(),

		// ── Python standard library ──────────────────────────────────────────
		pyHashlibAlgo(),
		pyHashlibNew(),
		pyHashlibPBKDF2(),
		pyHmacNew(),

		// ── PyCryptodome (Crypto.*) ──────────────────────────────────────────
		pycryptodomeAESNew(),
		pycryptodomeSymmetricNew(),
		pycryptodomeHashNew(),
		pycryptodomeRSAGenerate(),
		pycryptodomeECCGenerate(),
		pycryptodomeRSAEncrypt(),
		pycryptodomeHMAC(),
		pycryptodomeKDF(),

		// ── PyNaCl (libsodium) ───────────────────────────────────────────────
		pynaclSigningKey(),
		pynaclSecretBox(),
		pynaclPublicBox(),

		// ── PyJWT ────────────────────────────────────────────────────────────
		pyjwtEncode(),
		pyjwtDecode(),

		// ── passlib ──────────────────────────────────────────────────────────
		passlibHashUsing(),
		passlibCryptImport(),

		// ── paramiko (SSH) ───────────────────────────────────────────────────
		paramikoRSAKey(),
		paramikoECDSAKey(),
		paramikoDSSKey(),
		paramikoTransportAuth(),

		// ── gap-fill: bare imports / stdlib / DH / misc ──────────────────────
		pycaTripleDESBare(),
		pyDiffieHellmanKexClass(),
		pycaDHHazmat(),
		pyStdlibHMACBare(),
		pyOsUrandom(),
		pyHashlibBareCall(),
		pycaHashReference(),
		pynaclVerifyKey(),
		pycaECDSASign(),
		pycaX25519PublicKey(),
		pycaPKCS1v15(),
		pycaPKCS7(),
		pycaECCurveStandalone(),
		pycaModeReference(),
		pyInsecureRandom(),
	}
}

// ============================================================================
// pyca/cryptography
// ============================================================================

// --- Symmetric algorithms: algorithms.AES(key), algorithms.TripleDES(key), etc. ---

func pycaSymmetricAlgorithm() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-symmetric-algorithm",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`algorithms\s*\.\s*(AES|AES256|TripleDES|Camellia|CAST5|SEED|SM4|Blowfish|IDEA|ARC4|ChaCha20)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := classifyPycaPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- Cipher modes: modes.CBC(iv), modes.GCM(nonce), etc. ---

func pycaCipherMode() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-cipher-mode",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`modes\s*\.\s*(CBC|CTR|OFB|CFB|CFB8|GCM|XTS|ECB|SIV|CCM)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return []model.INode{model.NewMode(match[1])}
		},
	}
}

// --- AEAD ciphers: AESGCM(key), AESCCM(key), ChaCha20Poly1305(key), etc. ---

func pycaAEADCipher() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-aead",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`(?:aead\s*\.\s*|from\s+.*aead\s+import\s+.*\b)(AESGCM|AESCCM|AESGCMSIV|AESSIV|AESOCB3|ChaCha20Poly1305|XChaCha20Poly1305)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- Hash algorithms: hashes.SHA256(), hashes.SHA3_256(), etc. ---

func pycaHashAlgorithm() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-hash",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`hashes\s*\.\s*(SHA1|SHA224|SHA256|SHA384|SHA512|SHA512_224|SHA512_256|SHA3_224|SHA3_256|SHA3_384|SHA3_512|SHAKE128|SHAKE256|MD5|SM3|BLAKE2b|BLAKE2s)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := model.PrimitiveHash
			upper := strings.ToUpper(name)
			if strings.Contains(upper, "SHAKE") {
				prim = model.PrimitiveXOF
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- HMAC: hmac.HMAC(key, algorithm, ...) ---

func pycaHMAC() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-hmac",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`hmac\s*\.\s*HMAC\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HMAC", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// --- CMAC: CMAC(algorithm()) ---

func pycaCMAC() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-cmac",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`CMAC\s*\(\s*(\w+)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("CMAC", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// --- RSA key generation: rsa.generate_private_key(...) ---

func pycaRSAKeyGen() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-rsa-keygen",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`rsa\s*\.\s*generate_private_key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey("RSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- EC key generation: ec.generate_private_key(curve, ...) ---

func pycaECKeyGen() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ec-keygen",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`ec\s*\.\s*generate_private_key\s*\(\s*(?:ec\s*\.\s*)?(SECP\w+|SECT\w+|BrainpoolP\w+)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("EC", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			if len(match) >= 2 {
				algo.Put(model.NewEllipticCurve(match[1]))
			}
			privKey := model.NewKey("EC", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- DSA key generation: dsa.generate_private_key(key_size, ...) ---

func pycaDSAKeyGen() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-dsa-keygen",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`dsa\s*\.\s*generate_private_key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey("DSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- DH key generation: dh.generate_private_key ---

func pycaDHKeyGen() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-dh-keygen",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`dh\s*\.\s*generate_private_key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DH", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey("DH", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- Ed25519 ---

func pycaEd25519() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ed25519",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`Ed25519PrivateKey\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.Put(model.NewEllipticCurve("Ed25519"))
			privKey := model.NewKey("Ed25519", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- Ed448 ---

func pycaEd448() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ed448",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`Ed448PrivateKey\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed448", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.Put(model.NewEllipticCurve("Ed448"))
			privKey := model.NewKey("Ed448", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- X25519 ---

func pycaX25519() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-x25519",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`X25519PrivateKey\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X25519", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.Put(model.NewEllipticCurve("Curve25519"))
			privKey := model.NewKey("X25519", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- X448 ---

func pycaX448() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-x448",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`X448PrivateKey\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X448", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.Put(model.NewEllipticCurve("Curve448"))
			privKey := model.NewKey("X448", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- KDF: PBKDF2HMAC, Scrypt, HKDF, etc. ---

func pycaKDF() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-kdf",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`(?:kdf\w*\s*\.\s*)?(PBKDF2HMAC|Scrypt|HKDF|HKDFExpand|X963KDF|ConcatKDFHash|ConcatKDFHMAC|KBKDFHMAC|KBKDFCMAC)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := model.PrimitiveKeyDerivation
			upper := strings.ToUpper(name)
			if strings.Contains(upper, "PBKDF") || strings.Contains(upper, "SCRYPT") {
				prim = model.PrimitivePasswordHash
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- Fernet ---
// Fernet is a high-level wrapper that always uses AES-128-CBC + HMAC-SHA256.
// Emit the real underlying primitives so the CBOM reflects actual crypto in use.

func pycaFernet() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-fernet",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`Fernet\s*\(\s*|Fernet\s*\.\s*generate_key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			aes := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			aes.AddFunction(model.FuncEncrypt)
			aes.AddFunction(model.FuncDecrypt)
			aes.Put(model.NewMode("CBC"))
			aes.Put(model.NewKeyLength(128))

			hmac := model.NewAlgorithm("HMAC", model.PrimitiveMAC, loc)
			hmac.AddFunction(model.FuncTag)

			return []model.INode{aes, hmac}
		},
	}
}

// --- RSA signing: private_key.sign(..., padding.PSS/PKCS1v15, ...) ---

func pycaRSASign() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-rsa-sign",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`\.sign\s*\([^)]*padding\s*\.\s*(PSS|PKCS1v15)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("RSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			algo.Put(model.NewPadding(match[1]))
			return []model.INode{algo}
		},
	}
}

// --- EC signing: private_key.sign(data, ec.ECDSA(hash)) ---

func pycaECSign() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ec-sign",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`\.sign\s*\([^)]*(?:ec\s*\.\s*)?ECDSA\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// --- RSA encryption: public_key.encrypt(..., padding.OAEP/PKCS1v15) ---

func pycaRSAEncrypt() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-rsa-encrypt",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`\.encrypt\s*\([^)]*padding\s*\.\s*(OAEP|PKCS1v15)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.Put(model.NewPadding(match[1]))
			return []model.INode{algo}
		},
	}
}

// --- Cipher suite strings in SSL/TLS context ---

func pycaCipherSuite() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ciphersuite",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`["'](TLS_[A-Z0-9_]+)["']`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			cs := model.NewCipherSuite(match[1], loc)
			return []model.INode{cs}
		},
	}
}

// --- ssl.SSLContext / ssl.create_default_context ---

func pycaSSLContext() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ssl-context",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`ssl\s*\.\s*(?:SSLContext\s*\(\s*ssl\s*\.\s*PROTOCOL_(\w+)|create_default_context)\s*`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "TLS"
			if len(match) >= 2 && match[1] != "" {
				name = match[1]
			}
			proto := model.NewProtocol(name, loc)
			return []model.INode{proto}
		},
	}
}

// --- os.urandom(n) — OS-level CSPRNG ---

func pycaOsUrandom() *detection.Rule {
	return &detection.Rule{
		ID:        "pyca-os-urandom",
		Language:  detection.LangPython,
		Bundle:    "Pyca",
		Pattern:   regexp.MustCompile(`os\s*\.\s*urandom\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("os.urandom", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// --- secrets module: token_bytes, token_hex, token_urlsafe, randbits, SystemRandom ---

func pycaSecrets() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-secrets",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`secrets\s*\.\s*(token_bytes|token_hex|token_urlsafe|randbits|SystemRandom)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("secrets", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// --- Blake3: blake3.hash(...) / blake3.Blake3(...) ---
// Blake3 is not part of the standard cryptography library; it is provided
// by the standalone `blake3` PyPI package (import blake3).

func pycaBlake3() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-blake3",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`blake3\s*\.\s*(hash|Blake3|new)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("BLAKE3", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- liboqs-python: oqs.KeyEncapsulation("Kyber768") ---

func oqsKeyEncapsulation() *detection.Rule {
	return &detection.Rule{
		ID:       "liboqs-kem",
		Language: detection.LangPython,
		Bundle:   "liboqs",
		Pattern: regexp.MustCompile(
			`oqs\s*\.\s*KeyEncapsulation\s*\(\s*["']([^"']+)["']`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveKeyEncapsulation, loc)
			algo.AddFunction(model.FuncEncapsulate)
			algo.AddFunction(model.FuncDecapsulate)
			return []model.INode{algo}
		},
	}
}

// --- liboqs-python: oqs.Signature("Dilithium3") ---

func oqsSignature() *detection.Rule {
	return &detection.Rule{
		ID:       "liboqs-signature",
		Language: detection.LangPython,
		Bundle:   "liboqs",
		Pattern: regexp.MustCompile(
			`oqs\s*\.\s*Signature\s*\(\s*["']([^"']+)["']`),
		MatchType: detection.MatchFunctionCall,
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

// --- ML-DSA (FIPS 204 / Dilithium): MLDSAPrivateKey.generate(MLDSAParameters.MLDSA44) ---

func pycaMLDSA() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-mldsa",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`MLDSAPrivateKey\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ML-DSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey("ML-DSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- ML-KEM (FIPS 203 / Kyber): MLKEMPrivateKey.generate(MLKEMParameters.MLKEM512) ---

func pycaMLKEM() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-mlkem",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`MLKEMPrivateKey\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ML-KEM", model.PrimitiveKeyEncapsulation, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.AddFunction(model.FuncEncapsulate)
			algo.AddFunction(model.FuncDecapsulate)
			privKey := model.NewKey("ML-KEM", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{privKey}
		},
	}
}

// --- pyca native Argon2: Argon2id(...), Argon2i(...), Argon2d(...) ---
// from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

func pycaArgon2() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-argon2",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`\b(Argon2id|Argon2i|Argon2d)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- Poly1305 MAC: poly1305.Poly1305(key) ---
// from cryptography.hazmat.primitives.poly1305 import Poly1305

func pycaPoly1305() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-poly1305",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`(?:poly1305\s*\.\s*)?Poly1305\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Poly1305", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// --- ECDH key exchange: private_key.exchange(ec.ECDH(), peer_public_key) ---

func pycaECDHExchange() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ecdh-exchange",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`\.exchange\s*\(\s*(?:ec\s*\.\s*)?ECDH\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDH", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- pyca native bcrypt KDF: bcrypt(password, salt, rounds, backend) ---
// from cryptography.hazmat.primitives.kdf.bcrypt import bcrypt

func pycaBcrypt() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-bcrypt",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`from\s+cryptography[.\w]*kdf\.bcrypt\s+import\s+bcrypt|kdf\.bcrypt\.bcrypt\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- RSA decryption: private_key.decrypt(ciphertext, padding.OAEP/PKCS1v15) ---

func pycaRSADecrypt() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-rsa-decrypt",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`\.decrypt\s*\([^)]*padding\s*\.\s*(OAEP|PKCS1v15)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewPadding(match[1]))
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Python standard library (hashlib, hmac, random)
// ============================================================================

// --- hashlib.<algo>() — e.g. hashlib.sha256(), hashlib.md5() ---

func pyHashlibAlgo() *detection.Rule {
	return &detection.Rule{
		ID:       "py-hashlib-algo",
		Language: detection.LangPython,
		Bundle:   "hashlib",
		Pattern: regexp.MustCompile(
			`hashlib\s*\.\s*(md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|shake_128|shake_256|blake2b|blake2s|sm3)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
			name = strings.ReplaceAll(name, "_", "-")
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- hashlib.new("sha256", data) ---

func pyHashlibNew() *detection.Rule {
	return &detection.Rule{
		ID:       "py-hashlib-new",
		Language: detection.LangPython,
		Bundle:   "hashlib",
		Pattern: regexp.MustCompile(
			`hashlib\s*\.\s*new\s*\(\s*["']([^"']+)["']`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- hashlib.pbkdf2_hmac('sha256', password, salt, iterations) ---

func pyHashlibPBKDF2() *detection.Rule {
	return &detection.Rule{
		ID:       "py-hashlib-pbkdf2",
		Language: detection.LangPython,
		Bundle:   "hashlib",
		Pattern: regexp.MustCompile(
			`hashlib\s*\.\s*pbkdf2_hmac\s*\(\s*["']([^"']+)["']`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			hashName := strings.ToUpper(strings.ReplaceAll(match[1], "-", ""))
			name := "PBKDF2WithHmac" + hashName
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- hmac.new(key, msg, digestmod=hashlib.sha256) ---
// Python stdlib hmac module — distinct from pyca's hmac.HMAC().

func pyHmacNew() *detection.Rule {
	return &detection.Rule{
		ID:        "py-hmac-new",
		Language:  detection.LangPython,
		Bundle:    "hashlib",
		Pattern:   regexp.MustCompile(`\bhmac\s*\.\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HMAC", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// PyCryptodome (Crypto.*)
// ============================================================================

// --- AES.new(key, AES.MODE_CBC, iv) ---

func pycryptodomeAESNew() *detection.Rule {
	return &detection.Rule{
		ID:        "pycryptodome-aes-new",
		Language:  detection.LangPython,
		Bundle:    "PyCryptodome",
		Pattern:   regexp.MustCompile(`\bAES\s*\.\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- DES.new(), DES3.new(), Blowfish.new(), ARC4.new(), ChaCha20.new() etc. ---

func pycryptodomeSymmetricNew() *detection.Rule {
	return &detection.Rule{
		ID:       "pycryptodome-symmetric-new",
		Language: detection.LangPython,
		Bundle:   "PyCryptodome",
		Pattern: regexp.MustCompile(
			`\b(DES3|DES|ARC2|ARC4|Blowfish|CAST|ChaCha20|Salsa20|XSalsa20)\s*\.\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			var prim model.Primitive
			switch strings.ToUpper(name) {
			case "ARC4", "CHACHA20", "SALSA20", "XSALSA20":
				prim = model.PrimitiveStreamCipher
			default:
				prim = model.PrimitiveBlockCipher
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- MD5.new(), SHA256.new(), SHA1.new() etc. ---

func pycryptodomeHashNew() *detection.Rule {
	return &detection.Rule{
		ID:       "pycryptodome-hash-new",
		Language: detection.LangPython,
		Bundle:   "PyCryptodome",
		Pattern: regexp.MustCompile(
			`\b(MD5|MD4|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_256|SHA3_384|SHA3_512|BLAKE2b|BLAKE2s|RIPEMD160|keccak)\s*\.\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(strings.ToUpper(match[1]), model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- RSA.generate(2048) ---

func pycryptodomeRSAGenerate() *detection.Rule {
	return &detection.Rule{
		ID:        "pycryptodome-rsa-generate",
		Language:  detection.LangPython,
		Bundle:    "PyCryptodome",
		Pattern:   regexp.MustCompile(`\bRSA\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			key := model.NewKey("RSA", model.KindPrivateKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- ECC.generate(curve='P-256') ---

func pycryptodomeECCGenerate() *detection.Rule {
	return &detection.Rule{
		ID:        "pycryptodome-ecc-generate",
		Language:  detection.LangPython,
		Bundle:    "PyCryptodome",
		Pattern:   regexp.MustCompile(`\bECC\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("EC", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			key := model.NewKey("EC", model.KindPrivateKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- PKCS1_OAEP.new(key) / PKCS1_v1_5.new(key) ---

func pycryptodomeRSAEncrypt() *detection.Rule {
	return &detection.Rule{
		ID:       "pycryptodome-rsa-pkcs",
		Language: detection.LangPython,
		Bundle:   "PyCryptodome",
		Pattern: regexp.MustCompile(
			`\b(PKCS1_OAEP|PKCS1_v1_5|pkcs1_15)\s*\.\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			padding := "PKCS1v15"
			if strings.Contains(strings.ToUpper(match[1]), "OAEP") {
				padding = "OAEP"
			}
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.Put(model.NewPadding(padding))
			return []model.INode{algo}
		},
	}
}

// --- HMAC.new(key, digestmod=SHA256) ---

func pycryptodomeHMAC() *detection.Rule {
	return &detection.Rule{
		ID:        "pycryptodome-hmac",
		Language:  detection.LangPython,
		Bundle:    "PyCryptodome",
		Pattern:   regexp.MustCompile(`\bHMAC\s*\.\s*new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HMAC", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// --- PBKDF2(password, salt, ...) / scrypt(...) / bcrypt(...) ---

func pycryptodomeKDF() *detection.Rule {
	return &detection.Rule{
		ID:       "pycryptodome-kdf",
		Language: detection.LangPython,
		Bundle:   "PyCryptodome",
		Pattern: regexp.MustCompile(
			`\b(PBKDF2|scrypt|bcrypt)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
			prim := model.PrimitiveKeyDerivation
			if name == "PBKDF2" || name == "BCRYPT" {
				prim = model.PrimitivePasswordHash
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// PyNaCl (libsodium bindings)
// ============================================================================

// --- nacl.signing.SigningKey.generate() — Ed25519 ---

func pynaclSigningKey() *detection.Rule {
	return &detection.Rule{
		ID:       "pynacl-signing-key",
		Language: detection.LangPython,
		Bundle:   "PyNaCl",
		Pattern: regexp.MustCompile(
			`nacl\s*\.\s*signing\s*\.\s*SigningKey\s*\.\s*generate\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.Put(model.NewEllipticCurve("Ed25519"))
			key := model.NewKey("Ed25519", model.KindPrivateKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- nacl.secret.SecretBox(key) — XSalsa20-Poly1305 ---

func pynaclSecretBox() *detection.Rule {
	return &detection.Rule{
		ID:       "pynacl-secret-box",
		Language: detection.LangPython,
		Bundle:   "PyNaCl",
		Pattern: regexp.MustCompile(
			`nacl\s*\.\s*secret\s*\.\s*SecretBox\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("XSalsa20-Poly1305", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- nacl.public.Box(private_key, public_key) — Curve25519 + XSalsa20-Poly1305 ---

func pynaclPublicBox() *detection.Rule {
	return &detection.Rule{
		ID:       "pynacl-public-box",
		Language: detection.LangPython,
		Bundle:   "PyNaCl",
		Pattern: regexp.MustCompile(
			`nacl\s*\.\s*public\s*\.\s*Box\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Curve25519", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.Put(model.NewEllipticCurve("Curve25519"))
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// PyJWT
// ============================================================================

// --- jwt.encode(payload, key, algorithm="HS256") ---

func pyjwtEncode() *detection.Rule {
	return &detection.Rule{
		ID:       "pyjwt-encode",
		Language: detection.LangPython,
		Bundle:   "PyJWT",
		Pattern: regexp.MustCompile(
			`jwt\s*\.\s*encode\s*\([^)]*algorithm\s*=\s*["']([A-Za-z0-9]+)["']`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algoName := strings.ToUpper(match[1])
			prim := classifyJWTAlgorithm(algoName)
			algo := model.NewAlgorithm(algoName, prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// --- jwt.decode(token, key, algorithms=["RS256", ...]) ---

func pyjwtDecode() *detection.Rule {
	return &detection.Rule{
		ID:       "pyjwt-decode",
		Language: detection.LangPython,
		Bundle:   "PyJWT",
		Pattern: regexp.MustCompile(
			`jwt\s*\.\s*decode\s*\([^)]*algorithms\s*=\s*\[\s*["']([A-Za-z0-9]+)["']`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algoName := strings.ToUpper(match[1])
			prim := classifyJWTAlgorithm(algoName)
			algo := model.NewAlgorithm(algoName, prim, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Classification helpers
// ============================================================================

func classifyPycaPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case upper == "ARC4" || upper == "CHACHA20":
		return model.PrimitiveStreamCipher
	default:
		return model.PrimitiveBlockCipher
	}
}

// classifyJWTAlgorithm maps a JWT algorithm name to the closest model primitive.
// HS* = HMAC-based (symmetric), RS*/PS* = RSA, ES* = ECDSA, EdDSA/Ed* = EdDSA.
func classifyJWTAlgorithm(name string) model.Primitive {
	switch {
	case strings.HasPrefix(name, "HS"):
		return model.PrimitiveMAC
	case strings.HasPrefix(name, "RS"), strings.HasPrefix(name, "PS"):
		return model.PrimitiveSignature
	case strings.HasPrefix(name, "ES"):
		return model.PrimitiveSignature
	case name == "EDDSA", strings.HasPrefix(name, "ED"):
		return model.PrimitiveSignature
	case strings.EqualFold(name, "none"):
		// "none" disables signing — treated as MAC so CBOM-JWT-001 fires.
		return model.PrimitiveMAC
	default:
		return model.PrimitiveUnknown
	}
}

// ============================================================================
// passlib — Python password hashing library
// ============================================================================

// --- passlib.hash.<scheme>.using(...) / passlib.hash.<scheme>.hash(...) ---
// Detects password hashing scheme selection via the passlib library.
// e.g. from passlib.hash import md5_crypt, sha1_crypt, des_crypt, ldap_md5

func passlibHashUsing() *detection.Rule {
	return &detection.Rule{
		ID:       "passlib-hash-using",
		Language: detection.LangPython,
		Bundle:   "passlib",
		Pattern: regexp.MustCompile(
			`\b(md5_crypt|sha1_crypt|sha256_crypt|sha512_crypt|des_crypt|bsdi_crypt|ldap_md5|ldap_sha|ldap_salted_md5|ldap_salted_sha|atlassian_pbkdf2_sha1|django_salted_md5|django_salted_sha1|pbkdf2_sha1|pbkdf2_sha256|pbkdf2_sha512|bcrypt|bcrypt_sha256|argon2|scrypt|apr_md5_crypt)\s*\.\s*(hash|verify|using|identify|encrypt)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := passlibSchemeName(match[1])
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- from passlib.hash import md5_crypt ---
// Detects import of specific passlib hash schemes.

func passlibCryptImport() *detection.Rule {
	return &detection.Rule{
		ID:       "passlib-import",
		Language: detection.LangPython,
		Bundle:   "passlib",
		Pattern: regexp.MustCompile(
			`from\s+passlib\.hash\s+import\s+([\w\s,]+)`),
		MatchType: detection.MatchImport,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			var nodes []model.INode
			for _, scheme := range strings.Split(match[1], ",") {
				scheme = strings.TrimSpace(scheme)
				if scheme == "" {
					continue
				}
				name, prim := passlibSchemeName(scheme)
				algo := model.NewAlgorithm(name, prim, loc)
				algo.AddFunction(model.FuncKeyDerive)
				nodes = append(nodes, algo)
			}
			return nodes
		},
	}
}

func passlibSchemeName(scheme string) (string, model.Primitive) {
	switch scheme {
	case "md5_crypt", "apr_md5_crypt":
		return "MD5-crypt", model.PrimitivePasswordHash
	case "sha1_crypt":
		return "SHA1-crypt", model.PrimitivePasswordHash
	case "sha256_crypt":
		return "SHA256-crypt", model.PrimitivePasswordHash
	case "sha512_crypt":
		return "SHA512-crypt", model.PrimitivePasswordHash
	case "des_crypt", "bsdi_crypt":
		return "DES-crypt", model.PrimitivePasswordHash
	case "ldap_md5", "ldap_salted_md5":
		return "LDAP-MD5", model.PrimitivePasswordHash
	case "ldap_sha", "ldap_salted_sha":
		return "LDAP-SHA1", model.PrimitivePasswordHash
	case "django_salted_md5":
		return "Django-MD5", model.PrimitivePasswordHash
	case "django_salted_sha1", "atlassian_pbkdf2_sha1":
		return "Django-SHA1", model.PrimitivePasswordHash
	case "pbkdf2_sha1":
		return "PBKDF2-SHA1", model.PrimitivePasswordHash
	case "pbkdf2_sha256":
		return "PBKDF2-SHA256", model.PrimitivePasswordHash
	case "pbkdf2_sha512":
		return "PBKDF2-SHA512", model.PrimitivePasswordHash
	case "bcrypt", "bcrypt_sha256":
		return "bcrypt", model.PrimitivePasswordHash
	case "argon2":
		return "Argon2", model.PrimitivePasswordHash
	case "scrypt":
		return "scrypt", model.PrimitivePasswordHash
	default:
		return scheme, model.PrimitivePasswordHash
	}
}

// ============================================================================
// paramiko — Python SSH library
// ============================================================================

// --- paramiko.RSAKey.generate(bits=1024) ---

func paramikoRSAKey() *detection.Rule {
	return &detection.Rule{
		ID:       "paramiko-rsa-key",
		Language: detection.LangPython,
		Bundle:   "paramiko",
		Pattern: regexp.MustCompile(
			`paramiko\s*\.\s*RSAKey\s*\.\s*generate\s*\(\s*(?:bits\s*=\s*)?(\d+)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			key := model.NewKey("RSA", model.KindPrivateKey, loc)
			if len(match) >= 2 {
				if bits, err := strconv.Atoi(match[1]); err == nil {
					key.Put(model.NewKeyLength(bits))
				}
			}
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- paramiko.ECDSAKey.generate(bits=256) ---

func paramikoECDSAKey() *detection.Rule {
	return &detection.Rule{
		ID:       "paramiko-ecdsa-key",
		Language: detection.LangPython,
		Bundle:   "paramiko",
		Pattern: regexp.MustCompile(
			`paramiko\s*\.\s*ECDSAKey\s*\.\s*generate\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

// --- paramiko.DSSKey.generate(bits=1024) ---

func paramikoDSSKey() *detection.Rule {
	return &detection.Rule{
		ID:       "paramiko-dss-key",
		Language: detection.LangPython,
		Bundle:   "paramiko",
		Pattern: regexp.MustCompile(
			`paramiko\s*\.\s*DSSKey\s*\.\s*generate\s*\(\s*(?:bits\s*=\s*)?(\d+)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			key := model.NewKey("DSA", model.KindPrivateKey, loc)
			if len(match) >= 2 {
				if bits, err := strconv.Atoi(match[1]); err == nil {
					key.Put(model.NewKeyLength(bits))
				}
			}
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- paramiko.Transport: t.get_security_options().ciphers = ['aes128-cbc', 'des'] ---

func paramikoTransportAuth() *detection.Rule {
	return &detection.Rule{
		ID:       "paramiko-transport-ciphers",
		Language: detection.LangPython,
		Bundle:   "paramiko",
		Pattern: regexp.MustCompile(
			`get_security_options\s*\(\s*\)\s*\.\s*ciphers\s*=\s*\[([^\]]+)\]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			cipherPattern := regexp.MustCompile(`['"]([^'"]+)['"]`)
			ciphers := cipherPattern.FindAllStringSubmatch(match[1], -1)
			var nodes []model.INode
			for _, c := range ciphers {
				if len(c) < 2 {
					continue
				}
				cs := model.NewCipherSuite(c[1], loc)
				nodes = append(nodes, cs)
			}
			return nodes
		},
	}
}

// ============================================================================
// Additional gap-fill rules discovered via paramiko analysis
// ============================================================================

// --- TripleDES bare import: from cryptography...algorithms import TripleDES; TripleDES(key) ---
// Catches usages where TripleDES is imported directly and called without the
// "algorithms." prefix (e.g. paramiko/transport.py, paramiko/pkey.py).

func pycaTripleDESBare() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-tripledes-bare",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`\bTripleDES\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("3DES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- Diffie-Hellman key exchange: KexGroup1 / KexGroup14 / KexGroup16 / KexGex class names ---
// Paramiko defines DH kex via class attributes: name = "diffie-hellman-group1-sha1" etc.

func pyDiffieHellmanKexClass() *detection.Rule {
	return &detection.Rule{
		ID:       "py-dh-kex-class",
		Language: detection.LangPython,
		Bundle:   "paramiko",
		Pattern: regexp.MustCompile(
			`name\s*=\s*["'](diffie-hellman-[^"']+)["']`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("DH", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			cs := model.NewCipherSuite(match[1], loc)
			return []model.INode{algo, cs}
		},
	}
}

// --- Diffie-Hellman via cryptography.hazmat: dh.generate_parameters / dh.DHParameterNumbers ---

func pycaDHHazmat() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-dh-hazmat",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`dh\s*\.\s*(generate_parameters|DHParameterNumbers|DHParameters|generate_private_key)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DH", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

// --- stdlib hmac bare import: from hmac import HMAC; HMAC(key, msg, digest) ---
// Different from pyca's hmac.HMAC — this is Python's built-in hmac module.

func pyStdlibHMACBare() *detection.Rule {
	return &detection.Rule{
		ID:       "py-stdlib-hmac-bare",
		Language: detection.LangPython,
		Bundle:   "hmac",
		Pattern: regexp.MustCompile(
			`\bHMAC\s*\(\s*\w`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HMAC", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// --- os.urandom(n) — OS CSPRNG ---

func pyOsUrandom() *detection.Rule {
	return &detection.Rule{
		ID:       "py-os-urandom",
		Language: detection.LangPython,
		Bundle:   "hashlib",
		Pattern: regexp.MustCompile(
			`os\s*\.\s*urandom\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("os.urandom", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// --- Bare hashlib calls after from-import: md5(...), sha1(...), sha256(...) etc. ---
// Catches: from hashlib import md5, sha256; md5(data).digest()

func pyHashlibBareCall() *detection.Rule {
	return &detection.Rule{
		ID:       "py-hashlib-bare-call",
		Language: detection.LangPython,
		Bundle:   "hashlib",
		Pattern: regexp.MustCompile(
			`\b(md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|blake2b|blake2s)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
			name = strings.ReplaceAll(name, "_", "-")
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- hashes.SHA1 / hashes.SHA256 as class references (no parens) ---
// e.g. HASHES = {"ssh-rsa": hashes.SHA1, "rsa-sha2-256": hashes.SHA256}

func pycaHashReference() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-hash-reference",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`hashes\s*\.\s*(SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_224|SHA3_256|SHA3_384|SHA3_512|MD5|BLAKE2b|BLAKE2s)\b[^(]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- nacl.signing.VerifyKey ---

func pynaclVerifyKey() *detection.Rule {
	return &detection.Rule{
		ID:       "pynacl-verify-key",
		Language: detection.LangPython,
		Bundle:   "PyNaCl",
		Pattern: regexp.MustCompile(
			`nacl\s*\.\s*signing\s*\.\s*VerifyKey\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// --- ec.ECDSA(...) signing ---

func pycaECDSASign() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ecdsa-sign",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`ec\s*\.\s*ECDSA\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// --- X25519PublicKey.from_public_bytes(...) ---

func pycaX25519PublicKey() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-x25519-pubkey",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`X25519PublicKey\s*\.\s*from_public_bytes\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			key := model.NewKey("X25519", model.KindPublicKey, loc)
			return []model.INode{key}
		},
	}
}

// --- padding.PKCS1v15() ---

func pycaPKCS1v15() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-pkcs1v15",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`padding\s*\.\s*PKCS1v15\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PKCS1v15", model.PrimitiveUnknown, loc)
			return []model.INode{algo}
		},
	}
}

// --- padding.PKCS7(...) ---

func pycaPKCS7() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-pkcs7",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`padding\s*\.\s*PKCS7\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PKCS7", model.PrimitiveUnknown, loc)
			return []model.INode{algo}
		},
	}
}

// --- EC named curves as standalone references: ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1() ---

func pycaECCurveStandalone() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-ec-curve-standalone",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`ec\s*\.\s*(SECP192R1|SECP224R1|SECP256R1|SECP384R1|SECP521R1|SECP256K1|BrainpoolP256R1|BrainpoolP384R1|BrainpoolP512R1|SECT163K1|SECT233K1|SECT283K1|SECT409K1|SECT571K1)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveSignature, loc)
			return []model.INode{algo}
		},
	}
}

// --- modes.CBC / modes.CTR as class references (no parens) in dicts ---
// e.g. _CIPHER_TABLE = {"AES-128-CBC": {"mode": modes.CBC, ...}}

func pycaModeReference() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-mode-reference",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`modes\s*\.\s*(CBC|CTR|OFB|CFB|GCM|ECB|XTS|CCM|SIV)\b[^(]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return []model.INode{model.NewMode(match[1])}
		},
	}
}

// ============================================================================
// Insecure PRNG — Python stdlib random module
// ============================================================================

// pyInsecureRandom detects Python's built-in random module — the non-cryptographic
// PRNG seeded from os.urandom() but internally a Mersenne Twister (MT19937).
// Its internal state can be reconstructed from 624 consecutive outputs, making
// it unsuitable for security-sensitive values. Use the `secrets` module or
// os.urandom() for cryptographic purposes instead.
func pyInsecureRandom() *detection.Rule {
	return &detection.Rule{
		ID:       "py-random-insecure",
		Language: detection.LangPython,
		Bundle:   "PyStdlib",
		Pattern: regexp.MustCompile(
			`\brandom\s*\.\s*(random|randint|randrange|choice|choices|shuffle|sample|uniform|randbytes)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("random.random", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}
