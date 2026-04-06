package python

import (
	"regexp"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterPycaDetectionRules registers pyca/cryptography library detection rules.
func RegisterPycaDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range pycaRules() {
		registry.Register(r)
	}
}

func pycaRules() []*detection.Rule {
	return []*detection.Rule{
		pycaSymmetricAlgorithm(),
		pycaCipherMode(),
		pycaAEADCipher(),
		pycaHashAlgorithm(),
		pycaHMAC(),
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
	}
}

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
			`modes\s*\.\s*(CBC|CTR|OFB|CFB|CFB8|GCM|XTS|ECB)\s*\(`),
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
			`(?:aead\s*\.\s*|from\s+.*aead\s+import\s+.*\b)(AESGCM|AESCCM|AESGCMSIV|AESSIV|AEOCB3|ChaCha20Poly1305|XCHACHA20POLY1305)\s*\(`),
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

// --- DH key generation: dh.generate_parameters / generate_private_key ---

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

func pycaFernet() *detection.Rule {
	return &detection.Rule{
		ID:       "pyca-fernet",
		Language: detection.LangPython,
		Bundle:   "Pyca",
		Pattern: regexp.MustCompile(
			`Fernet\s*\(\s*|Fernet\s*\.\s*generate_key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Fernet", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
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

// --- Classification helper ---

func classifyPycaPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case upper == "ARC4" || upper == "CHACHA20":
		return model.PrimitiveStreamCipher
	default:
		return model.PrimitiveBlockCipher
	}
}
