package ruby

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterRubyDetectionRules registers all Ruby cryptography detection rules.
// Rules are grouped by source:
//   - OpenSSL    — Ruby stdlib (primary crypto library)
//   - Digest     — Ruby stdlib digest module
//   - BCrypt     — bcrypt gem
//   - jwt gem    — JSON Web Tokens
func RegisterRubyDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allRubyRules() {
		registry.Register(r)
	}
}

func allRubyRules() []*detection.Rule {
	return []*detection.Rule{
		// ── OpenSSL::Cipher ───────────────────────────────────────────────────
		rubyOpenSSLCipherNew(),
		rubyOpenSSLCipherAES(),
		// ── OpenSSL::Digest ───────────────────────────────────────────────────
		rubyOpenSSLDigestNew(),
		rubyOpenSSLDigestClass(),
		// ── OpenSSL::HMAC ─────────────────────────────────────────────────────
		rubyOpenSSLHMAC(),
		// ── OpenSSL::PKey — constructors ──────────────────────────────────────
		rubyOpenSSLPKeyRSA(),
		rubyOpenSSLPKeyEC(),
		rubyOpenSSLPKeyDSA(),
		rubyOpenSSLPKeyDH(),
		// ── OpenSSL::PKey — generic API (v3+) ────────────────────────────────
		rubyOpenSSLPKeyGenerate(),
		rubyOpenSSLPKeySign(),
		rubyOpenSSLPKeyVerify(),
		rubyOpenSSLPKeyDerive(),
		// ── OpenSSL::SSL ──────────────────────────────────────────────────────
		rubyOpenSSLSSLContext(),
		rubyOpenSSLSSLSocket(),
		rubyOpenSSLSSLCiphers(),
		rubyOpenSSLSSLVersion(),
		// ── OpenSSL::PKCS5 / OpenSSL::KDF ────────────────────────────────────
		rubyOpenSSLPKCS5PBKDF2(),
		rubyOpenSSLKDF(),
		// ── OpenSSL::Random ───────────────────────────────────────────────────
		rubyOpenSSLRandom(),
		// ── Digest stdlib ────────────────────────────────────────────────────
		rubyDigestClass(),
		rubyDigestHexdigest(),
		// ── BCrypt gem ───────────────────────────────────────────────────────
		rubyBcryptPasswordCreate(),
		rubyBcryptPasswordNew(),
		rubyBcryptEngineHash(),
		// ── jwt gem ──────────────────────────────────────────────────────────
		rubyJWTEncode(),
		rubyJWTDecode(),
		// ── SecureRandom stdlib ───────────────────────────────────────────────
		rubySecureRandom(),
		// ── Insecure PRNG (Kernel#rand / Random) ─────────────────────────────
		rubyInsecureRandom(),
		// ── Argon2 gem ────────────────────────────────────────────────────────
		rubyArgon2(),
	}
}

// ============================================================================
// OpenSSL::Cipher
// ============================================================================

// rubyOpenSSLCipherNew detects OpenSSL::Cipher.new('AES-256-CBC').
func rubyOpenSSLCipherNew() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-cipher-new",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*Cipher\s*\.\s*new\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractRubyCipher(match[1], loc)
		},
	}
}

// rubyOpenSSLCipherAES detects OpenSSL::Cipher::<Name>.new(...) for all named cipher subclasses.
func rubyOpenSSLCipherAES() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-cipher-aes",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*Cipher\s*::\s*(AES|DES|RC4|RC2|RC5|Blowfish|Camellia|CAST5|IDEA|AES128|AES192|AES256)\s*(?:\.\s*new)?\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeRubyCipherName(match[1])
			prim := model.PrimitiveBlockCipher
			if name == "RC4" {
				prim = model.PrimitiveStreamCipher
			}
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::Digest
// ============================================================================

// rubyOpenSSLDigestNew detects OpenSSL::Digest.new('SHA256').
func rubyOpenSSLDigestNew() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-digest-new",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*Digest\s*\.\s*new\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchMethodCall,
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

// rubyOpenSSLDigestClass detects OpenSSL::Digest::SHA256.new, OpenSSL::Digest::MD5.new, etc.
func rubyOpenSSLDigestClass() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-digest-class",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*Digest\s*::\s*(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|MD4|RIPEMD160)\s*(?:\.\s*new|\.\s*digest|\.\s*hexdigest)?\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(normalizeRubyHashName(match[1]), model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::HMAC
// ============================================================================

// rubyOpenSSLHMAC detects OpenSSL::HMAC.digest / hexdigest / base64digest / new.
func rubyOpenSSLHMAC() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-hmac",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*HMAC\s*\.\s*(?:digest|hexdigest|base64digest|new)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			// Extract hash from OpenSSL::Digest.new('SHA256') in the same pattern context
			hashMatch := regexp.MustCompile(`Digest(?:::\w+|\.new\s*\(\s*['"](\w+)['"])`).FindStringSubmatch(match[0])
			hashName := "SHA-256"
			if len(hashMatch) >= 2 && hashMatch[1] != "" {
				hashName = normalizeRubyHashName(hashMatch[1])
			}
			algo := model.NewAlgorithm("HMAC-"+hashName, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::PKey
// ============================================================================

// rubyOpenSSLPKeyRSA detects OpenSSL::PKey::RSA.new(2048).
func rubyOpenSSLPKeyRSA() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-rsa",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*PKey\s*::\s*RSA\s*\.\s*(?:new|generate)\s*\(\s*(\d+)?`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			if len(match) >= 2 && match[1] != "" {
				if bits := parseRubyInt(match[1]); bits > 0 {
					algo.Put(model.NewKeyLength(bits))
				}
			}
			pubKey := model.NewKey("RSA", model.KindPublicKey, loc)
			pubKey.Put(algo)
			privKey := model.NewKey("RSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{pubKey, privKey}
		},
	}
}

// rubyOpenSSLPKeyEC detects OpenSSL::PKey::EC.new('prime256v1').
func rubyOpenSSLPKeyEC() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-ec",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*PKey\s*::\s*EC\s*\.\s*(?:new|generate_key)\s*\(\s*['"]?([^'",)]+)['"]?`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			curve := "P-256"
			if len(match) >= 2 && match[1] != "" {
				curve = normalizeRubyECCurve(strings.TrimSpace(match[1]))
			}
			algo := model.NewAlgorithm("ECDSA-"+curve, model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			pubKey := model.NewKey("ECDSA-"+curve, model.KindPublicKey, loc)
			pubKey.Put(algo)
			privKey := model.NewKey("ECDSA-"+curve, model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{pubKey, privKey}
		},
	}
}

func rubyOpenSSLPKeyDSA() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-dsa",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*PKey\s*::\s*DSA\s*\.\s*(?:new|generate)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

func rubyOpenSSLPKeyDH() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-dh",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*PKey\s*::\s*DH\s*\.\s*(?:new|generate)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DH", model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::SSL
// ============================================================================

func rubyOpenSSLSSLContext() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-ssl-context",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*SSL\s*::\s*SSLContext\s*\.\s*new\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

func rubyOpenSSLSSLSocket() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-ssl-socket",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*SSL\s*::\s*SSLSocket\s*\.\s*new\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

// rubyOpenSSLSSLCiphers detects ctx.ciphers = 'RC4:...' / set_params(ciphers: '...')
// cipher strings set on an SSLContext, recording each suite as a CipherSuite node.
func rubyOpenSSLSSLCiphers() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-ssl-ciphers",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`(?:\.ciphers\s*=\s*|ciphers\s*:\s*)['"]([^'"]+)['"]`),
		MatchType: detection.MatchMethodCall,
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
// OpenSSL::PKCS5
// ============================================================================

func rubyOpenSSLPKCS5PBKDF2() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkcs5-pbkdf2",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		// Distinguish pbkdf2_hmac_sha1 (always SHA1) from generic pbkdf2_hmac (needs hash arg).
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*PKCS5\s*\.\s*(pbkdf2_hmac_sha1|pbkdf2_hmac)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "PBKDF2"
			if len(match) >= 2 && match[1] == "pbkdf2_hmac_sha1" {
				name = "PBKDF2WithHmacSHA1"
			}
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::Random
// ============================================================================

func rubyOpenSSLRandom() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-random",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*Random\s*\.\s*(?:random_bytes|pseudo_bytes)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("OpenSSL::Random", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Digest stdlib
// ============================================================================

// rubyDigestClass detects Digest::SHA256.hexdigest(...), Digest::MD5.digest(...), etc.
func rubyDigestClass() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-digest-class",
		Language:  detection.LangRuby,
		Bundle:    "RubyDigest",
		Pattern:   regexp.MustCompile(`\bDigest\s*::\s*(SHA1|SHA256|SHA384|SHA512|MD5|RMD160|SHA2)\s*(?:\.\s*new|\.\s*digest|\.\s*hexdigest)?\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(normalizeRubyHashName(match[1]), model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// rubyDigestHexdigest detects Digest::SHA256.hexdigest(data) class-method form.
func rubyDigestHexdigest() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-digest-hexdigest",
		Language:  detection.LangRuby,
		Bundle:    "RubyDigest",
		Pattern:   regexp.MustCompile(`Digest\s*::\s*(SHA1|SHA256|SHA384|SHA512|MD5)\s*\.\s*(?:hexdigest|base64digest|bubblebabble)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(normalizeRubyHashName(match[1]), model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// BCrypt gem
// ============================================================================

// rubyBcryptPasswordCreate detects BCrypt::Password.create(password).
func rubyBcryptPasswordCreate() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-bcrypt-create",
		Language:  detection.LangRuby,
		Bundle:    "RubyBcrypt",
		Pattern:   regexp.MustCompile(`BCrypt\s*::\s*Password\s*\.\s*create\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// jwt gem
// ============================================================================

// rubyJWTEncode detects JWT.encode(payload, secret, 'HS256').
func rubyJWTEncode() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-jwt-encode",
		Language:  detection.LangRuby,
		Bundle:    "RubyJWT",
		Pattern:   regexp.MustCompile(`JWT\s*\.\s*encode\s*\([^,]+,[^,]+,\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := rubyJWTAlgorithmPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// rubyJWTDecode detects JWT.decode(token, secret, true, algorithms: ['RS256']).
func rubyJWTDecode() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-jwt-decode",
		Language:  detection.LangRuby,
		Bundle:    "RubyJWT",
		Pattern:   regexp.MustCompile(`JWT\s*\.\s*decode\s*\([^)]*algorithms\s*:\s*\[\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := rubyJWTAlgorithmPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// SecureRandom stdlib
// ============================================================================

func rubySecureRandom() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-securerandom",
		Language:  detection.LangRuby,
		Bundle:    "RubyStdlib",
		Pattern:   regexp.MustCompile(`SecureRandom\s*\.\s*(?:random_bytes|hex|base64|urlsafe_base64|uuid|alphanumeric)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SecureRandom", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Insecure PRNG — Kernel#rand / Random
// ============================================================================

// rubyInsecureRandom detects Ruby's built-in non-cryptographic random sources:
//   - rand(n) / rand()          — Kernel#rand, seeded from the clock
//   - Random.rand(n)            — explicit call on the default PRNG
//   - Random.new(seed)          — deterministic seeded PRNG instance
//
// These are NOT cryptographically secure and must not be used for tokens,
// passwords, nonces, or any security-sensitive value. Use SecureRandom instead.
func rubyInsecureRandom() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-insecure-random",
		Language:  detection.LangRuby,
		Bundle:    "RubyStdlib",
		Pattern:   regexp.MustCompile(`\brand\s*\(|\bRandom\s*\.\s*(?:rand|new)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Kernel#rand", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::PKey — generic v3+ API
// ============================================================================

// rubyOpenSSLPKeyGenerate detects OpenSSL::PKey.generate_key("RSA", {...})
// and OpenSSL::PKey.generate_parameters("DH", {...}) — the preferred API
// since OpenSSL 3.x / ruby/openssl 3.0.
func rubyOpenSSLPKeyGenerate() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-generate",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*PKey\s*\.\s*(?:generate_key|generate_parameters)\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := rubyPKeyNameAndPrimitive(match[1])
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

// rubyOpenSSLPKeySign detects key.sign(digest, data) and key.sign_raw(nil, data)
// used for RSA/EC/DSA signing via the generic PKey API.
func rubyOpenSSLPKeySign() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-sign",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`\.(?:sign_raw|sign)\s*\(\s*(?:OpenSSL::Digest|['"][a-zA-Z0-9_-]+['"]|nil)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PKey/sign", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// rubyOpenSSLPKeyVerify detects key.verify(digest, sig, data) and
// key.verify_raw(nil, sig, data) used for RSA/EC/DSA signature verification.
func rubyOpenSSLPKeyVerify() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-verify",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`\.(?:verify_raw|verify)\s*\(\s*(?:OpenSSL::Digest|['"][a-zA-Z0-9_-]+['"]|nil)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PKey/verify", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// rubyOpenSSLPKeyDerive detects key.derive(other_pubkey) — ECDH / DH shared
// secret derivation using the modern OpenSSL::PKey API.
// Also catches EC#dh_compute_key and DH#compute_key (older compat methods).
func rubyOpenSSLPKeyDerive() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-pkey-derive",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`\.(?:derive|dh_compute_key|compute_key)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "ECDH"
			if strings.Contains(match[0], "compute_key") && !strings.Contains(match[0], "dh_compute_key") {
				name = "DH"
			}
			algo := model.NewAlgorithm(name, model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::KDF — key derivation module (ruby/openssl 2.2+)
// ============================================================================

// rubyOpenSSLKDF detects OpenSSL::KDF.pbkdf2_hmac, OpenSSL::KDF.scrypt, and
// OpenSSL::KDF.hkdf — the modern KDF API that replaces PKCS5 wrappers.
func rubyOpenSSLKDF() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-kdf",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`OpenSSL\s*::\s*KDF\s*\.\s*(pbkdf2_hmac|scrypt|hkdf)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			var name string
			switch strings.ToLower(match[1]) {
			case "scrypt":
				name = "scrypt"
			case "hkdf":
				name = "HKDF"
			default:
				name = "PBKDF2"
			}
			algo := model.NewAlgorithm(name, model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// OpenSSL::SSL — TLS version configuration
// ============================================================================

// rubyOpenSSLSSLVersion detects explicit TLS version pinning:
//
//	ctx.ssl_version = :TLSv1    (deprecated, forces a single version)
//	ctx.min_version = OpenSSL::SSL::TLS1_VERSION
//	ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
func rubyOpenSSLSSLVersion() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-openssl-ssl-version",
		Language:  detection.LangRuby,
		Bundle:    "RubyOpenSSL",
		Pattern:   regexp.MustCompile(`\.(?:ssl_version|min_version|max_version)\s*=\s*(.+)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			version := "TLS"
			if len(match) >= 2 {
				val := strings.TrimSpace(match[1])
				switch {
				case strings.Contains(val, "SSL2") || strings.Contains(val, "SSLv2"):
					version = "SSLv2"
				case strings.Contains(val, "SSL3") || strings.Contains(val, "SSLv3"):
					version = "SSLv3"
				case strings.Contains(val, "TLS1_1") || strings.Contains(val, "TLSv1_1"):
					version = "TLS1.1"
				case strings.Contains(val, "TLS1_2") || strings.Contains(val, "TLSv1_2"):
					version = "TLS1.2"
				case strings.Contains(val, "TLS1") || strings.Contains(val, "TLSv1"):
					version = "TLS1.0"
				}
			}
			return []model.INode{model.NewProtocol(version, loc)}
		},
	}
}

// ============================================================================
// BCrypt gem — Devise-specific usage patterns
// ============================================================================

// rubyBcryptPasswordNew detects BCrypt::Password.new(hashed_string) — loads
// an existing bcrypt hash for comparison, used by Devise's encryptor.
func rubyBcryptPasswordNew() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-bcrypt-password-new",
		Language:  detection.LangRuby,
		Bundle:    "RubyBcrypt",
		Pattern:   regexp.MustCompile(`BCrypt\s*::\s*Password\s*\.\s*new\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// rubyBcryptEngineHash detects BCrypt::Engine.hash_secret(password, salt) —
// the low-level bcrypt computation called by Devise when verifying passwords.
func rubyBcryptEngineHash() *detection.Rule {
	return &detection.Rule{
		ID:        "ruby-bcrypt-engine-hash",
		Language:  detection.LangRuby,
		Bundle:    "RubyBcrypt",
		Pattern:   regexp.MustCompile(`BCrypt\s*::\s*Engine\s*\.\s*hash_secret\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Helper functions
// ============================================================================

// extractRubyCipher parses cipher strings like 'AES-256-CBC', 'DES-EDE3-CBC'.
// The algorithm node is named with the BASE cipher name (e.g. "AES", "DES", "3DES")
// so that vulnerability rules fire correctly. Mode and key length are child nodes.
func extractRubyCipher(raw string, loc model.DetectionLocation) []model.INode {
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
	if strings.Contains(upper, "GCM") || strings.Contains(upper, "CCM") {
		prim = model.PrimitiveAEAD
	} else if algoName == "RC4" {
		prim = model.PrimitiveStreamCipher
	}

	algo := model.NewAlgorithm(algoName, prim, loc)
	algo.AddFunction(model.FuncEncrypt)
	algo.AddFunction(model.FuncDecrypt)

	// Extract key size when the second segment is numeric (e.g. AES-256-CBC → 256 bits).
	if len(parts) >= 2 {
		if keyBits, err := strconv.Atoi(parts[1]); err == nil && keyBits > 0 {
			algo.Put(model.NewKeyLength(keyBits))
		}
	}

	if len(parts) >= 3 {
		mode := parts[len(parts)-1]
		switch mode {
		case "CBC", "GCM", "CTR", "CFB", "OFB", "ECB", "CCM":
			algo.Put(model.NewMode(mode))
		}
	}
	return []model.INode{algo}
}

func normalizeRubyCipherName(name string) string {
	switch strings.ToUpper(name) {
	case "AES128":
		return "AES-128"
	case "AES192":
		return "AES-192"
	case "AES256":
		return "AES-256"
	default:
		return strings.ToUpper(name)
	}
}

func normalizeRubyHashName(name string) string {
	switch strings.ToUpper(name) {
	case "SHA1":
		return "SHA-1"
	case "SHA256", "SHA2":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	case "MD5":
		return "MD5"
	case "RMD160", "RIPEMD160":
		return "RIPEMD-160"
	default:
		return strings.ToUpper(name)
	}
}

func normalizeRubyECCurve(curve string) string {
	switch strings.ToLower(curve) {
	case "prime256v1", "secp256r1":
		return "P-256"
	case "secp384r1":
		return "P-384"
	case "secp521r1":
		return "P-521"
	case "secp256k1":
		return "secp256k1"
	default:
		return curve
	}
}

// rubyPKeyNameAndPrimitive maps an OpenSSL algorithm string like "RSA", "EC",
// "DH", "DSA" to a canonical name and the appropriate CBOM primitive.
func rubyPKeyNameAndPrimitive(raw string) (string, model.Primitive) {
	upper := strings.ToUpper(strings.TrimSpace(raw))
	switch upper {
	case "RSA":
		return "RSA", model.PrimitivePublicKeyEncryption
	case "EC":
		return "EC", model.PrimitiveSignature
	case "DSA":
		return "DSA", model.PrimitiveSignature
	case "DH":
		return "DH", model.PrimitiveKeyAgreement
	case "ED25519", "EDDSA":
		return "Ed25519", model.PrimitiveSignature
	case "X25519":
		return "X25519", model.PrimitiveKeyAgreement
	default:
		return raw, model.PrimitiveUnknown
	}
}

func rubyJWTAlgorithmPrimitive(alg string) model.Primitive {
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

func parseRubyInt(s string) int {
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

// ============================================================================
// Argon2 gem
// ============================================================================

// rubyArgon2 detects usage of the `argon2` gem for password hashing:
//   - Argon2::Password.create(password, ...)
//   - Argon2::Password.new(hash)
//   - Argon2::Password.verify_password(hash, password)
func rubyArgon2() *detection.Rule {
	return &detection.Rule{
		ID:       "ruby-argon2",
		Language: detection.LangRuby,
		Bundle:   "RubyArgon2",
		Pattern:  regexp.MustCompile(`\bArgon2\s*::\s*Password\s*\.\s*(create|new|verify_password)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Argon2", model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}
