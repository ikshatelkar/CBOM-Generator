package php

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterPHPDetectionRules registers all PHP cryptography detection rules.
// Rules are grouped by source:
//   - openssl_*      — built-in OpenSSL functions
//   - hash / hash_hmac — built-in hashing
//   - password_hash  — built-in password hashing (bcrypt, argon2)
//   - sodium_*       — libsodium PHP extension
//   - mcrypt_*       — deprecated legacy extension (still in old codebases)
func RegisterPHPDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allPHPRules() {
		registry.Register(r)
	}
}

func allPHPRules() []*detection.Rule {
	return []*detection.Rule{
		// ── openssl_* ─────────────────────────────────────────────────────────
		phpOpenSSLEncrypt(),
		phpOpenSSLDecrypt(),
		phpOpenSSLSign(),
		phpOpenSSLVerify(),
		phpOpenSSLPkeyNew(),
		phpOpenSSLDigest(),
		phpOpenSSLRandomPseudoBytes(),
		// ── hash / hash_hmac ──────────────────────────────────────────────────
		phpHashFunction(),
		phpHashHmac(),
		phpHashPBKDF2(),
		// ── password_hash ─────────────────────────────────────────────────────
		phpPasswordHash(),
		// ── sodium_* ──────────────────────────────────────────────────────────
		phpSodiumAEAD(),
		phpSodiumSecretbox(),
		phpSodiumBox(),
		phpSodiumSign(),
		phpSodiumHash(),
		phpSodiumPwhash(),
		phpSodiumKDF(),
		// ── mcrypt_* (deprecated) ─────────────────────────────────────────────
		phpMcryptEncrypt(),
		// ── TLS stream context ciphers ────────────────────────────────────────
		phpStreamContextSSLCiphers(),
	}
}

// ============================================================================
// openssl_* built-in functions
// ============================================================================

// phpOpenSSLEncrypt detects openssl_encrypt($data, 'aes-256-cbc', $key, ...).
func phpOpenSSLEncrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-encrypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_encrypt\s*\([^,]+,\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractPHPCipherAlgo(match[1], loc, true)
		},
	}
}

func phpOpenSSLDecrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-decrypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_decrypt\s*\([^,]+,\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractPHPCipherAlgo(match[1], loc, false)
		},
	}
}

// phpOpenSSLSign detects openssl_sign($data, $sig, $key, OPENSSL_ALGO_SHA256).
func phpOpenSSLSign() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-sign",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_sign\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func phpOpenSSLVerify() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-verify",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_verify\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLPkeyNew detects openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, ...]).
func phpOpenSSLPkeyNew() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-pkey-new",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_pkey_new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			// Determine key type from the same line if possible
			name := "RSA"
			prim := model.PrimitivePublicKeyEncryption
			lineUpper := strings.ToUpper(match[0])
			switch {
			case strings.Contains(lineUpper, "EC"):
				name = "EC"
				prim = model.PrimitiveSignature
			case strings.Contains(lineUpper, "DSA"):
				name = "DSA"
				prim = model.PrimitiveSignature
			case strings.Contains(lineUpper, "DH"):
				name = "DH"
				prim = model.PrimitiveKeyAgreement
			}
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

// phpOpenSSLDigest detects openssl_digest($data, 'sha256').
func phpOpenSSLDigest() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-digest",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_digest\s*\([^,]+,\s*['"]([^'"]+)['"]`),
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

func phpOpenSSLRandomPseudoBytes() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-random",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_random_pseudo_bytes\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("openssl_random_pseudo_bytes", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// hash() / hash_hmac()
// ============================================================================

// phpHashFunction detects hash('sha256', $data), hash('md5', ...), etc.
func phpHashFunction() *detection.Rule {
	return &detection.Rule{
		ID:        "php-hash",
		Language:  detection.LangPHP,
		Bundle:    "PHPHash",
		Pattern:   regexp.MustCompile(`\bhash\s*\(\s*['"]([^'"]+)['"]`),
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

// phpHashHmac detects hash_hmac('sha256', $data, $key).
func phpHashHmac() *detection.Rule {
	return &detection.Rule{
		ID:        "php-hash-hmac",
		Language:  detection.LangPHP,
		Bundle:    "PHPHash",
		Pattern:   regexp.MustCompile(`hash_hmac\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := "HMAC-" + strings.ToUpper(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

func phpHashPBKDF2() *detection.Rule {
	return &detection.Rule{
		ID:        "php-hash-pbkdf2",
		Language:  detection.LangPHP,
		Bundle:    "PHPHash",
		Pattern:   regexp.MustCompile(`hash_pbkdf2\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("PBKDF2-"+strings.ToUpper(match[1]), model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// password_hash()
// ============================================================================

// phpPasswordHash detects password_hash($password, PASSWORD_BCRYPT), PASSWORD_ARGON2ID, etc.
func phpPasswordHash() *detection.Rule {
	return &detection.Rule{
		ID:        "php-password-hash",
		Language:  detection.LangPHP,
		Bundle:    "PHPPasswordHash",
		Pattern:   regexp.MustCompile(`password_hash\s*\([^,]+,\s*(PASSWORD_\w+)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizePHPPasswordAlgo(match[1])
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// sodium_* functions (libsodium PHP extension)
// ============================================================================

// phpSodiumAEAD detects sodium_crypto_aead_aes256gcm_encrypt, sodium_crypto_aead_chacha20poly1305_encrypt, etc.
func phpSodiumAEAD() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-aead",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_aead_(aes256gcm|chacha20poly1305|chacha20poly1305_ietf|xchacha20poly1305_ietf)_(encrypt|decrypt)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 3 {
				return nil
			}
			name := normalizeSodiumAEADName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveAEAD, loc)
			if match[2] == "encrypt" {
				algo.AddFunction(model.FuncEncrypt)
			} else {
				algo.AddFunction(model.FuncDecrypt)
			}
			return []model.INode{algo}
		},
	}
}

func phpSodiumSecretbox() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-secretbox",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_secretbox(?:_open)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NaCl/secretbox", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func phpSodiumBox() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-box",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_box(?:_keypair|_open|_seal|_seal_open)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NaCl/box", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func phpSodiumSign() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-sign",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_sign(?:_open|_detached|_verify_detached|_keypair|_seed_keypair)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

func phpSodiumHash() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-hash",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_generichash(?:_init|_update|_final)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("BLAKE2b", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func phpSodiumPwhash() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-pwhash",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_pwhash(?:_str|_str_verify|_scryptsalsa208sha256)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "Argon2id"
			if strings.Contains(match[0], "scrypt") {
				name = "scrypt"
			}
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func phpSodiumKDF() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-kdf",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_kdf_derive_from_key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("BLAKE2b-KDF", model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// mcrypt_* (deprecated)
// ============================================================================

// phpMcryptEncrypt detects mcrypt_encrypt(MCRYPT_RIJNDAEL_256, ...) — deprecated since PHP 7.1.
func phpMcryptEncrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-mcrypt-encrypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPMcrypt",
		Pattern:   regexp.MustCompile(`mcrypt_encrypt\s*\(\s*(MCRYPT_\w+|['"][^'"]+['"])`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			raw := strings.TrimPrefix(strings.Trim(match[1], `"'`), "MCRYPT_")
			name := normalizeMcryptName(raw)
			algo := model.NewAlgorithm(name, model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// TLS stream context ciphers
// ============================================================================

// phpStreamContextSSLCiphers detects 'ciphers' in SSL stream context options:
// stream_context_create(['ssl' => ['ciphers' => 'RC4:...']])
func phpStreamContextSSLCiphers() *detection.Rule {
	return &detection.Rule{
		ID:        "php-stream-ssl-ciphers",
		Language:  detection.LangPHP,
		Bundle:    "PHPTLS",
		Pattern:   regexp.MustCompile(`['"]ciphers['"]\s*=>\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			parts := strings.Split(match[1], ":")
			var nodes []model.INode
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					nodes = append(nodes, model.NewCipherSuite(p, loc))
				}
			}
			return nodes
		},
	}
}

// ============================================================================
// Helper functions
// ============================================================================

// extractPHPCipherAlgo parses OpenSSL cipher strings like 'aes-256-cbc', 'des-ede3-cbc'.
// The algorithm node is named with the BASE cipher name (e.g. "AES", "DES", "3DES")
// so that vulnerability rules fire correctly. Mode and key length are child nodes.
func extractPHPCipherAlgo(raw string, loc model.DetectionLocation, encrypt bool) []model.INode {
	upper := strings.ToUpper(raw)
	parts := strings.Split(upper, "-")

	// Derive the canonical base algorithm name.
	algoName := parts[0]
	switch {
	case algoName == "DES" && len(parts) > 1 && (parts[1] == "EDE3" || parts[1] == "EDE"):
		algoName = "3DES"
	case algoName == "BF":
		algoName = "Blowfish"
	case algoName == "CAMELLIA":
		algoName = "Camellia"
	}

	prim := model.PrimitiveBlockCipher
	if strings.Contains(upper, "GCM") || strings.Contains(upper, "CCM") || strings.Contains(upper, "OCB") {
		prim = model.PrimitiveAEAD
	}

	algo := model.NewAlgorithm(algoName, prim, loc)
	if encrypt {
		algo.AddFunction(model.FuncEncrypt)
	} else {
		algo.AddFunction(model.FuncDecrypt)
	}

	// Extract key size when the second segment is numeric (e.g. aes-256-cbc → 256 bits).
	if len(parts) >= 2 {
		if keyBits, err := strconv.Atoi(parts[1]); err == nil && keyBits > 0 {
			algo.Put(model.NewKeyLength(keyBits))
		}
	}

	// Extract mode from last segment.
	if len(parts) >= 3 {
		mode := parts[len(parts)-1]
		switch mode {
		case "CBC", "GCM", "CTR", "CFB", "OFB", "ECB", "CCM", "OCB":
			algo.Put(model.NewMode(mode))
		}
	}
	return []model.INode{algo}
}

func normalizePHPPasswordAlgo(constant string) string {
	switch constant {
	case "PASSWORD_BCRYPT":
		return "bcrypt"
	case "PASSWORD_ARGON2I":
		return "Argon2i"
	case "PASSWORD_ARGON2ID":
		return "Argon2id"
	default:
		return strings.TrimPrefix(constant, "PASSWORD_")
	}
}

func normalizeSodiumAEADName(name string) string {
	switch name {
	case "aes256gcm":
		return "AES-256-GCM"
	case "chacha20poly1305", "chacha20poly1305_ietf":
		return "ChaCha20-Poly1305"
	case "xchacha20poly1305_ietf":
		return "XChaCha20-Poly1305"
	default:
		return strings.ToUpper(name)
	}
}

func normalizeMcryptName(name string) string {
	switch name {
	case "RIJNDAEL_128", "RIJNDAEL_192", "RIJNDAEL_256":
		return "AES"
	case "3DES", "TRIPLEDES":
		return "3DES"
	case "BLOWFISH":
		return "Blowfish"
	case "CAST_128", "CAST_256":
		return "CAST"
	default:
		return name
	}
}
