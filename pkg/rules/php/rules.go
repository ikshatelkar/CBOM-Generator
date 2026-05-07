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
		phpOpenSSLEncryptDynamic(),
		phpOpenSSLDecryptDynamic(),
		phpOpenSSLSign(),
		phpOpenSSLVerify(),
		phpOpenSSLPkeyNew(),
		phpOpenSSLDigest(),
		phpOpenSSLRandomPseudoBytes(),
		phpOpenSSLPublicEncrypt(),
		phpOpenSSLPrivateDecrypt(),
		phpOpenSSLPrivateEncrypt(),
		phpOpenSSLPublicDecrypt(),
		phpOpenSSLSeal(),
		phpOpenSSLOpen(),
		phpOpenSSLPkcs7Sign(),
		phpOpenSSLPkcs7Verify(),
		phpOpenSSLCsrNew(),
		// ── hash / hash_hmac / streaming hash ────────────────────────────────
		phpHashFunction(),
		phpHashHmac(),
		phpHashPBKDF2(),
		phpHashInit(),
		// ── md5 / sha1 native shortcuts ───────────────────────────────────────
		phpMd5(),
		phpSha1(),
		// ── password_hash / password_verify ───────────────────────────────────
		phpPasswordHash(),
		phpPasswordHashDynamic(),
		phpPasswordVerify(),
		phpCrypt(),
		// ── PHP built-in CSPRNG ───────────────────────────────────────────────
		phpRandomBytes(),
		phpRandomInt(),
		// ── sodium_* ──────────────────────────────────────────────────────────
		phpSodiumAEAD(),
		phpSodiumSecretbox(),
		phpSodiumBox(),
		phpSodiumSign(),
		phpSodiumHash(),
		phpSodiumPwhash(),
		phpSodiumKDF(),
		phpSodiumScalarMult(),
		phpSodiumAuth(),
		phpSodiumShortHash(),
		// ── mcrypt_* (deprecated) ─────────────────────────────────────────────
		phpMcryptEncrypt(),
		// ── TLS stream context ciphers ────────────────────────────────────────
		phpStreamContextSSLCiphers(),
		// ── phpseclib — symmetric ciphers (new ClassName('mode')) ─────────────
		phpSecLibAES(),
		phpSecLibTripleDES(),
		phpSecLibDES(),
		phpSecLibRijndael(),
		phpSecLibBlowfish(),
		phpSecLibTwofish(),
		phpSecLibRC4(),
		phpSecLibChaCha20(),
		phpSecLibSalsa20(),
		// ── phpseclib — asymmetric / key-exchange (Class::createKey()) ────────
		phpSecLibRSACreateKey(),
		phpSecLibECCreateKey(),
		phpSecLibDSACreateKey(),
		phpSecLibDHCreateKey(),
		phpSecLibDHComputeSecret(),
		// ── phpseclib — Hash object & CSPRNG ──────────────────────────────────
		phpSecLibHash(),
		phpSecLibRandom(),
		// ── Third-party JWT (firebase/php-jwt) ────────────────────────────────
		phpFirebaseJWTEncode(),
		phpFirebaseJWTDecode(),
		// ── Insecure PRNG ─────────────────────────────────────────────────────
		phpInsecureRandom(),
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

// nonCryptoPHPHashAlgos lists names that PHP's hash/hash_hmac/hash_pbkdf2 accept
// but are either non-cryptographic (xxHash, CRC, FNV, …) or obvious
// test/placeholder strings. We skip these to avoid false positives.
var nonCryptoPHPHashAlgos = map[string]bool{
	// xxHash — fast non-cryptographic hashes (PHP 8.1+)
	"XXH3": true, "XXH128": true, "XXH32": true, "XXH64": true,
	// CRC / Adler
	"CRC32": true, "CRC32B": true, "CRC32C": true, "ADLER32": true,
	// FNV
	"FNV132": true, "FNV1A32": true, "FNV164": true, "FNV1A64": true,
	// Jenkins
	"JOAAT": true,
	// Common test / placeholder strings
	"FOO": true, "BAR": true, "BAZ": true, "ABCDEF": true, "TEST": true,
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
			if nonCryptoPHPHashAlgos[name] {
				return nil
			}
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
			upper := strings.ToUpper(match[1])
			if nonCryptoPHPHashAlgos[upper] {
				return nil
			}
			algo := model.NewAlgorithm("HMAC-"+upper, model.PrimitiveMAC, loc)
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
			upper := strings.ToUpper(match[1])
			if nonCryptoPHPHashAlgos[upper] {
				return nil
			}
			algo := model.NewAlgorithm("PBKDF2-"+upper, model.PrimitivePasswordHash, loc)
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
// phpseclib — symmetric ciphers
// Detects: new AES('cbc'), new TripleDES('cbc'), new DES('ecb'), etc.
// ============================================================================

// phpSecLibAES detects: new AES('cbc'), new AES('gcm'), new AES('ctr'), etc.
func phpSecLibAES() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-aes",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+AES\s*\(\s*['"]([^'"]*)['"]\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			mode := "CBC"
			if len(match) >= 2 && match[1] != "" {
				mode = strings.ToUpper(match[1])
			}
			prim := model.PrimitiveBlockCipher
			if mode == "GCM" || mode == "CCM" || mode == "OCB" {
				prim = model.PrimitiveAEAD
			}
			algo := model.NewAlgorithm("AES", prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode(mode))
			return []model.INode{algo}
		},
	}
}

// phpSecLibTripleDES detects: new TripleDES('cbc'), new TripleDES('ctr'), etc.
func phpSecLibTripleDES() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-tripledes",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+TripleDES\s*\(\s*['"]([^'"]*)['"]\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			mode := "CBC"
			if len(match) >= 2 && match[1] != "" {
				mode = strings.ToUpper(match[1])
			}
			algo := model.NewAlgorithm("3DES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode(mode))
			return []model.INode{algo}
		},
	}
}

// phpSecLibDES detects: new DES('cbc'), new DES('ecb'), etc.
func phpSecLibDES() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-des",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+DES\s*\(\s*['"]([^'"]*)['"]\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			mode := "CBC"
			if len(match) >= 2 && match[1] != "" {
				mode = strings.ToUpper(match[1])
			}
			algo := model.NewAlgorithm("DES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode(mode))
			return []model.INode{algo}
		},
	}
}

// phpSecLibRijndael detects: new Rijndael('cbc'), new Rijndael('gcm'), etc.
func phpSecLibRijndael() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-rijndael",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+Rijndael\s*\(\s*['"]([^'"]*)['"]\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			mode := "CBC"
			if len(match) >= 2 && match[1] != "" {
				mode = strings.ToUpper(match[1])
			}
			prim := model.PrimitiveBlockCipher
			if mode == "GCM" || mode == "CCM" {
				prim = model.PrimitiveAEAD
			}
			algo := model.NewAlgorithm("Rijndael", prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode(mode))
			return []model.INode{algo}
		},
	}
}

// phpSecLibBlowfish detects: new Blowfish('cbc'), new Blowfish('ctr'), etc.
func phpSecLibBlowfish() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-blowfish",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+Blowfish\s*\(\s*['"]([^'"]*)['"]\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			mode := "CBC"
			if len(match) >= 2 && match[1] != "" {
				mode = strings.ToUpper(match[1])
			}
			algo := model.NewAlgorithm("Blowfish", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode(mode))
			return []model.INode{algo}
		},
	}
}

// phpSecLibTwofish detects: new Twofish('cbc'), new Twofish('ctr'), etc.
func phpSecLibTwofish() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-twofish",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+Twofish\s*\(\s*['"]([^'"]*)['"]\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			mode := "CBC"
			if len(match) >= 2 && match[1] != "" {
				mode = strings.ToUpper(match[1])
			}
			algo := model.NewAlgorithm("Twofish", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode(mode))
			return []model.INode{algo}
		},
	}
}

// phpSecLibRC4 detects: new RC4() — broken stream cipher.
func phpSecLibRC4() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-rc4",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+RC4\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RC4", model.PrimitiveStreamCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// phpSecLibChaCha20 detects: new ChaCha20()
func phpSecLibChaCha20() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-chacha20",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+ChaCha20\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ChaCha20", model.PrimitiveStreamCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// phpSecLibSalsa20 detects: new Salsa20()
func phpSecLibSalsa20() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-salsa20",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+Salsa20\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Salsa20", model.PrimitiveStreamCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// phpseclib — asymmetric / key-exchange static factory methods
// ============================================================================

// phpSecLibRSACreateKey detects: RSA::createKey(2048)
func phpSecLibRSACreateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-rsa-createkey",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`RSA::createKey\s*\(\s*(\d+)?`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			if len(match) >= 2 && match[1] != "" {
				if bits, err := strconv.Atoi(match[1]); err == nil {
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

// phpSecLibECCreateKey detects: EC::createKey('secp256r1'), EC::createKey('Ed25519'), etc.
func phpSecLibECCreateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-ec-createkey",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`EC::createKey\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			curve := "EC"
			if len(match) >= 2 {
				curve = match[1]
			}
			name, prim := classifyPHPSecLibECCurve(curve)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey(name, model.KindPrivateKey, loc)
			privKey.Put(algo)
			pubKey := model.NewKey(name, model.KindPublicKey, loc)
			pubKey.Put(algo)
			return []model.INode{privKey, pubKey}
		},
	}
}

// phpSecLibDSACreateKey detects: DSA::createKey(...) and DSA::createParameters(...)
func phpSecLibDSACreateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-dsa-createkey",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`DSA::(?:createKey|createParameters)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey("DSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			pubKey := model.NewKey("DSA", model.KindPublicKey, loc)
			pubKey.Put(algo)
			return []model.INode{privKey, pubKey}
		},
	}
}

// phpSecLibDHCreateKey detects: DH::createKey(...) and DH::createParameters(...)
func phpSecLibDHCreateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-dh-createkey",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`DH::(?:createKey|createParameters)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DH", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			privKey := model.NewKey("DH", model.KindPrivateKey, loc)
			privKey.Put(algo)
			pubKey := model.NewKey("DH", model.KindPublicKey, loc)
			pubKey.Put(algo)
			return []model.INode{privKey, pubKey}
		},
	}
}

// phpSecLibDHComputeSecret detects: DH::computeSecret($private, $public)
func phpSecLibDHComputeSecret() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-dh-computesecret",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`DH::computeSecret\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DH", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// phpseclib — Hash object and CSPRNG
// ============================================================================

// phpSecLibHash detects: new Hash('sha256'), new Hash('md5'), new Hash('sha3-256'), etc.
func phpSecLibHash() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-hash",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`new\s+Hash\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizePHPSecLibHashName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// phpSecLibRandom detects: Random::string($length) — phpseclib CSPRNG.
func phpSecLibRandom() *detection.Rule {
	return &detection.Rule{
		ID:        "php-phpseclib-random",
		Language:  detection.LangPHP,
		Bundle:    "PHPSecLib",
		Pattern:   regexp.MustCompile(`Random::string\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("CSPRNG", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// openssl_* RSA direct encryption / hybrid encryption / PKCS#7 / CSR
// ============================================================================

// phpOpenSSLPublicEncrypt detects openssl_public_encrypt($data, $encrypted, $pubKey).
func phpOpenSSLPublicEncrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-public-encrypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_public_encrypt\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncEncrypt)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLPrivateDecrypt detects openssl_private_decrypt($encrypted, $decrypted, $privKey).
func phpOpenSSLPrivateDecrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-private-decrypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_private_decrypt\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLPrivateEncrypt detects openssl_private_encrypt() — raw RSA sign operation.
func phpOpenSSLPrivateEncrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-private-encrypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_private_encrypt\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLPublicDecrypt detects openssl_public_decrypt() — raw RSA verify operation.
func phpOpenSSLPublicDecrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-public-decrypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_public_decrypt\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLSeal detects openssl_seal($data, $sealed, $envKeys, $pubKeys, $method).
// Hybrid encryption: random symmetric key encrypted with RSA public key(s).
func phpOpenSSLSeal() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-seal",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_seal\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			rsa := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			rsa.AddFunction(model.FuncEncrypt)
			sym := model.NewAlgorithm("OpenSSL/seal", model.PrimitiveBlockCipher, loc)
			sym.AddFunction(model.FuncEncrypt)
			return []model.INode{rsa, sym}
		},
	}
}

// phpOpenSSLOpen detects openssl_open($sealed, $open, $envKey, $privKey, $method).
func phpOpenSSLOpen() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-open",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_open\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			rsa := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			rsa.AddFunction(model.FuncDecrypt)
			sym := model.NewAlgorithm("OpenSSL/seal", model.PrimitiveBlockCipher, loc)
			sym.AddFunction(model.FuncDecrypt)
			return []model.INode{rsa, sym}
		},
	}
}

// phpOpenSSLPkcs7Sign detects openssl_pkcs7_sign() — S/MIME email signing.
func phpOpenSSLPkcs7Sign() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-pkcs7-sign",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_pkcs7_sign\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PKCS7", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLPkcs7Verify detects openssl_pkcs7_verify() — S/MIME signature verification.
func phpOpenSSLPkcs7Verify() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-pkcs7-verify",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_pkcs7_verify\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PKCS7", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLCsrNew detects openssl_csr_new($dn, $privKey, $config) — X.509 CSR generation.
func phpOpenSSLCsrNew() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-csr-new",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_csr_new\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X.509-CSR", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// md5() / sha1() native shortcuts
// ============================================================================

// phpMd5 detects md5($data) — insecure hash, extremely common in legacy PHP.
func phpMd5() *detection.Rule {
	return &detection.Rule{
		ID:        "php-md5",
		Language:  detection.LangPHP,
		Bundle:    "PHPHash",
		Pattern:   regexp.MustCompile(`\bmd5\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("MD5", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// phpSha1 detects sha1($data) — collision-broken hash, still widely used.
func phpSha1() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sha1",
		Language:  detection.LangPHP,
		Bundle:    "PHPHash",
		Pattern:   regexp.MustCompile(`\bsha1\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SHA1", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// hash_init() — context/streaming hash API
// ============================================================================

// phpHashInit detects hash_init('sha256') and hash_init('sha256', HASH_HMAC, $key).
func phpHashInit() *detection.Rule {
	return &detection.Rule{
		ID:        "php-hash-init",
		Language:  detection.LangPHP,
		Bundle:    "PHPHash",
		Pattern:   regexp.MustCompile(`hash_init\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
			// When HASH_HMAC flag is present on the same line treat as MAC.
			prim := model.PrimitiveHash
			fn := model.FuncDigest
			if strings.Contains(match[0], "HASH_HMAC") {
				name = "HMAC-" + name
				prim = model.PrimitiveMAC
				fn = model.FuncTag
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(fn)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// crypt() — legacy password hashing
// ============================================================================

// phpCrypt detects crypt($password, $salt) — algorithm determined by salt prefix.
// $2y$ = bcrypt, $5$ = sha256-crypt, $6$ = sha512-crypt, $1$ = MD5-crypt, no prefix = DES.
func phpCrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-crypt",
		Language:  detection.LangPHP,
		Bundle:    "PHPPasswordHash",
		Pattern:   regexp.MustCompile(`\bcrypt\s*\(\s*[^,]+,\s*['"](\$[^'"]+|[^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "DES-crypt"
			if len(match) >= 2 {
				salt := match[1]
				switch {
				case strings.HasPrefix(salt, "$2y$") || strings.HasPrefix(salt, "$2b$") || strings.HasPrefix(salt, "$2a$"):
					name = "bcrypt"
				case strings.HasPrefix(salt, "$5$"):
					name = "sha256-crypt"
				case strings.HasPrefix(salt, "$6$"):
					name = "sha512-crypt"
				case strings.HasPrefix(salt, "$1$"):
					name = "MD5-crypt"
				}
			}
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// sodium_* — additional primitives
// ============================================================================

// phpSodiumScalarMult detects sodium_crypto_scalarmult() and
// sodium_crypto_scalarmult_base() — X25519 Diffie-Hellman key exchange.
func phpSodiumScalarMult() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-scalarmult",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_scalarmult(?:_base)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X25519", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// phpSodiumAuth detects sodium_crypto_auth() and sodium_crypto_auth_verify()
// — HMAC-SHA512256 MAC.
func phpSodiumAuth() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-auth",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_auth(?:_verify)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HMAC-SHA512256", model.PrimitiveMAC, loc)
			if strings.Contains(match[0], "_verify") {
				algo.AddFunction(model.FuncVerify)
			} else {
				algo.AddFunction(model.FuncTag)
			}
			return []model.INode{algo}
		},
	}
}

// phpSodiumShortHash detects sodium_crypto_shorthash() — SipHash-2-4 keyed hash
// used for hash tables and short inputs (NOT collision-resistant for general use).
func phpSodiumShortHash() *detection.Rule {
	return &detection.Rule{
		ID:        "php-sodium-shorthash",
		Language:  detection.LangPHP,
		Bundle:    "PHPSodium",
		Pattern:   regexp.MustCompile(`sodium_crypto_shorthash\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SipHash-2-4", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Third-party JWT — firebase/php-jwt
// ============================================================================

// phpFirebaseJWTEncode detects JWT::encode($payload, $key, 'HS256') from
// the firebase/php-jwt library (most popular PHP JWT implementation).
func phpFirebaseJWTEncode() *detection.Rule {
	return &detection.Rule{
		ID:        "php-firebase-jwt-encode",
		Language:  detection.LangPHP,
		Bundle:    "PHPFirebaseJWT",
		Pattern:   regexp.MustCompile(`JWT::encode\s*\([^,]+,[^,]+,\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractJWTAlgorithm(match[1], loc, model.FuncSign)
		},
	}
}

// phpFirebaseJWTDecode detects JWT::decode($token, new Key($secret, 'HS256')) or
// JWT::decode($token, $key) where the Key object captures the algorithm.
func phpFirebaseJWTDecode() *detection.Rule {
	return &detection.Rule{
		ID:        "php-firebase-jwt-decode",
		Language:  detection.LangPHP,
		Bundle:    "PHPFirebaseJWT",
		Pattern:   regexp.MustCompile(`JWT::decode\s*\([^,]+,\s*new\s+Key\s*\([^,]+,\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractJWTAlgorithm(match[1], loc, model.FuncVerify)
		},
	}
}

// phpOpenSSLEncryptDynamic detects openssl_encrypt() where the cipher is passed
// as a variable rather than a string literal (e.g. strtolower($this->cipher)).
func phpOpenSSLEncryptDynamic() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-encrypt-dynamic",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_encrypt\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			line := match[0]
			// Skip if already captured by the literal-string rule.
			if regexp.MustCompile(`openssl_encrypt\s*\([^,]+,\s*['"]`).MatchString(line) {
				return nil
			}
			algo := model.NewAlgorithm("OpenSSL", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			return []model.INode{algo}
		},
	}
}

// phpOpenSSLDecryptDynamic detects openssl_decrypt() where the cipher is a variable.
func phpOpenSSLDecryptDynamic() *detection.Rule {
	return &detection.Rule{
		ID:        "php-openssl-decrypt-dynamic",
		Language:  detection.LangPHP,
		Bundle:    "PHPOpenSSL",
		Pattern:   regexp.MustCompile(`openssl_decrypt\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			line := match[0]
			if regexp.MustCompile(`openssl_decrypt\s*\([^,]+,\s*['"]`).MatchString(line) {
				return nil
			}
			algo := model.NewAlgorithm("OpenSSL", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// phpPasswordHashDynamic detects password_hash() where the algorithm constant is
// passed via a method call or variable (e.g. $this->algorithm()).
func phpPasswordHashDynamic() *detection.Rule {
	return &detection.Rule{
		ID:        "php-password-hash-dynamic",
		Language:  detection.LangPHP,
		Bundle:    "PHPPasswordHash",
		Pattern:   regexp.MustCompile(`password_hash\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			line := match[0]
			// Skip if already captured by the literal-constant rule.
			if regexp.MustCompile(`password_hash\s*\([^,]+,\s*PASSWORD_\w+`).MatchString(line) {
				return nil
			}
			algo := model.NewAlgorithm("password_hash", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// phpPasswordVerify detects password_verify($plain, $hash) used to verify
// passwords hashed with password_hash().
func phpPasswordVerify() *detection.Rule {
	return &detection.Rule{
		ID:        "php-password-verify",
		Language:  detection.LangPHP,
		Bundle:    "PHPPasswordHash",
		Pattern:   regexp.MustCompile(`password_verify\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("password_verify", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// phpRandomBytes detects random_bytes($n) — PHP's built-in CSPRNG for
// generating cryptographically secure raw bytes (used for IVs, tokens, keys).
func phpRandomBytes() *detection.Rule {
	return &detection.Rule{
		ID:        "php-random-bytes",
		Language:  detection.LangPHP,
		Bundle:    "PHPCSPRNG",
		Pattern:   regexp.MustCompile(`\brandom_bytes\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("random_bytes", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// phpRandomInt detects random_int($min, $max) — PHP's built-in CSPRNG for
// generating a cryptographically secure random integer.
func phpRandomInt() *detection.Rule {
	return &detection.Rule{
		ID:        "php-random-int",
		Language:  detection.LangPHP,
		Bundle:    "PHPCSPRNG",
		Pattern:   regexp.MustCompile(`\brandom_int\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("random_int", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
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

// classifyPHPSecLibECCurve returns the canonical algorithm name and primitive for a phpseclib EC curve string.
func classifyPHPSecLibECCurve(curve string) (string, model.Primitive) {
	lower := strings.ToLower(curve)
	switch {
	case lower == "ed25519":
		return "Ed25519", model.PrimitiveSignature
	case lower == "ed448":
		return "Ed448", model.PrimitiveSignature
	case lower == "curve25519" || lower == "x25519":
		return "X25519", model.PrimitiveKeyAgreement
	case lower == "curve448" || lower == "x448":
		return "X448", model.PrimitiveKeyAgreement
	case strings.Contains(lower, "secp256r1") || strings.Contains(lower, "prime256v1"):
		return "ECDSA/P-256", model.PrimitiveSignature
	case strings.Contains(lower, "secp384r1"):
		return "ECDSA/P-384", model.PrimitiveSignature
	case strings.Contains(lower, "secp521r1"):
		return "ECDSA/P-521", model.PrimitiveSignature
	default:
		return "EC/" + curve, model.PrimitiveSignature
	}
}

// extractJWTAlgorithm maps a JWT algorithm string (e.g. "HS256", "RS512", "ES384")
// to a CBOM algorithm node.
func extractJWTAlgorithm(alg string, loc model.DetectionLocation, fn model.CryptoFunc) []model.INode {
	upper := strings.ToUpper(alg)
	var name string
	var prim model.Primitive
	switch {
	case strings.HasPrefix(upper, "HS"):
		name = "HMAC-SHA" + upper[2:]
		prim = model.PrimitiveMAC
	case strings.HasPrefix(upper, "RS"):
		name = "RSA"
		prim = model.PrimitiveSignature
	case strings.HasPrefix(upper, "PS"):
		name = "RSA-PSS"
		prim = model.PrimitiveSignature
	case strings.HasPrefix(upper, "ES"):
		name = "ECDSA"
		prim = model.PrimitiveSignature
	case upper == "EDDSA" || upper == "ED25519":
		name = "Ed25519"
		prim = model.PrimitiveSignature
	default:
		name = upper
		prim = model.PrimitiveSignature
	}
	algo := model.NewAlgorithm(name, prim, loc)
	algo.AddFunction(fn)
	return []model.INode{algo}
}

// ============================================================================
// Insecure PRNG — rand() / mt_rand()
// ============================================================================

// phpInsecureRandom detects PHP's non-cryptographic random functions rand() and
// mt_rand() (Mersenne Twister). These are seeded from the system clock and are
// predictable. They must not be used for tokens, nonces, passwords, or any
// security-sensitive value. Use random_bytes() or random_int() instead.
func phpInsecureRandom() *detection.Rule {
	return &detection.Rule{
		ID:       "php-rand-insecure",
		Language: detection.LangPHP,
		Bundle:   "PHPCore",
		Pattern:  regexp.MustCompile(`\b(rand|mt_rand|lcg_value|shuffle)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("rand", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// normalizePHPSecLibHashName normalises phpseclib hash algorithm strings.
func normalizePHPSecLibHashName(name string) string {
	lower := strings.ToLower(name)
	switch lower {
	case "md5":
		return "MD5"
	case "sha1", "sha-1":
		return "SHA1"
	case "sha256", "sha-256":
		return "SHA256"
	case "sha384", "sha-384":
		return "SHA384"
	case "sha512", "sha-512":
		return "SHA512"
	case "sha3-256":
		return "SHA3-256"
	case "sha3-384":
		return "SHA3-384"
	case "sha3-512":
		return "SHA3-512"
	case "blake2b256", "blake2b-256":
		return "BLAKE2b-256"
	case "blake2b512", "blake2b-512":
		return "BLAKE2b-512"
	default:
		return strings.ToUpper(name)
	}
}
