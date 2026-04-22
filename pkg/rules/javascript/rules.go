package javascript

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterJSDetectionRules registers all JavaScript crypto detection rules.
func RegisterJSDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allJSRules(detection.LangJavaScript) {
		registry.Register(r)
	}
}

// RegisterTSDetectionRules registers all TypeScript crypto detection rules.
// TypeScript uses the same npm libraries as JavaScript, so the rule patterns
// are identical — only the Language tag differs.
func RegisterTSDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allJSRules(detection.LangTypeScript) {
		registry.Register(r)
	}
}

func allJSRules(lang detection.Language) []*detection.Rule {
	return []*detection.Rule{
		// ── Node.js built-in crypto module ────────────────────────────────────
		nodeCryptoCreateCipher(lang),
		nodeCryptoCreateCipheriv(lang),
		nodeCryptoCreateDecipheriv(lang),
		nodeCryptoCreateHash(lang),
		nodeCryptoCreateHmac(lang),
		nodeCryptoGenerateKeyPair(lang),
		nodeCryptoSign(lang),
		nodeCryptoVerify(lang),
		nodeCryptoRandomBytes(lang),
		nodeCryptoPBKDF2(lang),
		nodeCryptoScrypt(lang),
		nodeCryptoHKDF(lang),
		nodeCryptoDiffieHellman(lang),
		// ── Web Crypto API (crypto.subtle) ────────────────────────────────────
		subtleEncrypt(lang),
		subtleDecrypt(lang),
		subtleDigest(lang),
		subtleGenerateKey(lang),
		subtleImportKey(lang),
		subtleSign(lang),
		subtleVerify(lang),
		subtleDeriveKey(lang),
		subtleDeriveBits(lang),
		// ── jsonwebtoken (npm) ────────────────────────────────────────────
		jwtSign(lang),
		jwtVerify(lang),
		jwtNoneAlgorithm(lang),
		// ── TLS server cipher strings ──────────────────────────────────────
		nodeTLSCiphers(lang),
		// ── jose (npm) ────────────────────────────────────────────────────────
		joseSignJWT(lang),
		joseEncryptJWT(lang),
		joseAlgorithm(lang),
		// ── bcrypt / bcryptjs ─────────────────────────────────────────────────
		bcryptHash(lang),
		// ── argon2 (npm) ─────────────────────────────────────────────────────
		argon2Hash(lang),
		// ── crypto-js ────────────────────────────────────────────────────────
		cryptoJSAlgo(lang),
		cryptoJSHmac(lang),
		// ── tweetnacl ────────────────────────────────────────────────────────
		naclSecretbox(lang),
		naclBox(lang),
		naclSign(lang),
		// ── node-forge ───────────────────────────────────────────────────────
		forgeCipher(lang),
		forgeDigest(lang),
		forgePKI(lang),
	}
}

// ============================================================================
// Node.js built-in crypto module
// ============================================================================

// nodeCryptoCreateCipher detects the deprecated crypto.createCipher('des-cbc', key) API
// (no explicit IV — Node.js derives the IV from the key using a weak KDF).
// This is more dangerous than createCipheriv and is commonly found in legacy code.
func nodeCryptoCreateCipher(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-createcipher",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`(?:crypto|require\s*\(\s*['"](?:node:)?crypto['"]\s*\))\s*\.\s*createCipher\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractNodeCipherAlgo(match[1], loc, true)
		},
	}
}

// nodeCryptoCreateCipheriv detects crypto.createCipheriv('aes-256-cbc', key, iv).
func nodeCryptoCreateCipheriv(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-createcipheriv",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`(?:crypto|require\s*\(\s*['"](?:node:)?crypto['"]\s*\))\s*\.\s*createCipheriv\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractNodeCipherAlgo(match[1], loc, true)
		},
	}
}

func nodeCryptoCreateDecipheriv(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-createdecipheriv",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.createDecipheriv\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			return extractNodeCipherAlgo(match[1], loc, false)
		},
	}
}

// nodeCryptoCreateHash detects crypto.createHash('sha256').
func nodeCryptoCreateHash(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-createhash",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.createHash\s*\(\s*['"]([^'"]+)['"]`),
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

// nodeCryptoCreateHmac detects crypto.createHmac('sha256', key).
func nodeCryptoCreateHmac(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-createhmac",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.createHmac\s*\(\s*['"]([^'"]+)['"]`),
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

// nodeCryptoGenerateKeyPair detects crypto.generateKeyPair('rsa', { modulusLength: 2048 }, ...).
func nodeCryptoGenerateKeyPair(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-generatekeypair",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.generateKeyPair(?:Sync)?\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
			prim := classifyJSAsymmetricPrimitive(name)
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

func nodeCryptoSign(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-sign",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`(?:^|[^a-zA-Z])crypto\.sign\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(strings.ToUpper(match[1]), model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func nodeCryptoVerify(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-verify",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`(?:^|[^a-zA-Z])crypto\.verify\s*\(\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(strings.ToUpper(match[1]), model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

func nodeCryptoRandomBytes(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-randombytes",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.randomBytes\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("crypto.randomBytes", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

func nodeCryptoPBKDF2(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-pbkdf2",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.pbkdf2(?:Sync)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PBKDF2", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func nodeCryptoScrypt(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-scrypt",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.scrypt(?:Sync)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("scrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func nodeCryptoHKDF(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-hkdf",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.hkdf(?:Sync)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HKDF", model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func nodeCryptoDiffieHellman(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-node-crypto-dh",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\.createDiffieHellman(?:Group)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DH", model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Web Crypto API (crypto.subtle)
// ============================================================================

// subtleEncrypt detects crypto.subtle.encrypt({ name: 'AES-GCM' }, ...).
func subtleEncrypt(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-encrypt",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.encrypt\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := classifyWebCryptoAlgo(match[1])
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncEncrypt)
			return []model.INode{algo}
		},
	}
}

func subtleDecrypt(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-decrypt",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.decrypt\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := classifyWebCryptoAlgo(match[1])
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// subtleDigest detects crypto.subtle.digest('SHA-256', data).
func subtleDigest(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-digest",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.digest\s*\(\s*['"]([^'"]+)['"]`),
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

func subtleGenerateKey(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-generatekey",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.generateKey\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := classifyWebCryptoAlgo(match[1])
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

func subtleImportKey(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-importkey",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.importKey\s*\([^,]+,[^,]+,\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name, prim := classifyWebCryptoAlgo(match[1])
			key := model.NewKey(name, model.KindKey, loc)
			algo := model.NewAlgorithm(name, prim, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

func subtleSign(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-sign",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.sign\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func subtleVerify(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-verify",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.verify\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

func subtleDeriveKey(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-derivekey",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.deriveKey\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := model.PrimitiveKeyDerivation
			if strings.Contains(strings.ToUpper(match[1]), "PBKDF") {
				prim = model.PrimitivePasswordHash
			}
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func subtleDeriveBits(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-subtle-derivebits",
		Language:  lang,
		Bundle:    "WebCrypto",
		Pattern:   regexp.MustCompile(`subtle\.deriveBits\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// jsonwebtoken (npm)
// ============================================================================

// jwtSign detects jwt.sign(payload, secret, { algorithm: 'HS256' }).
func jwtSign(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-jwt-sign",
		Language:  lang,
		Bundle:    "JSJWT",
		Pattern:   regexp.MustCompile(`\bjwt\.sign\s*\([^)]*algorithm\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := jsJWTAlgorithmPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func jwtVerify(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-jwt-verify",
		Language:  lang,
		Bundle:    "JSJWT",
		Pattern:   regexp.MustCompile(`\bjwt\.verify\s*\([^)]*algorithms\s*:\s*\[\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := jsJWTAlgorithmPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// jose (npm)
// ============================================================================

func joseSignJWT(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-jose-signjwt",
		Language:  lang,
		Bundle:    "JoseJWT",
		Pattern:   regexp.MustCompile(`new\s+SignJWT\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("JWT", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func joseEncryptJWT(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-jose-encryptjwt",
		Language:  lang,
		Bundle:    "JoseJWT",
		Pattern:   regexp.MustCompile(`new\s+EncryptJWT\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("JWE", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncEncrypt)
			return []model.INode{algo}
		},
	}
}

// joseAlgorithm detects .setProtectedHeader({ alg: 'RS256' }) or alg: 'HS256' in jose calls.
func joseAlgorithm(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-jose-algorithm",
		Language:  lang,
		Bundle:    "JoseJWT",
		Pattern:   regexp.MustCompile(`alg\s*:\s*['"]([A-Z0-9]+(?:-[A-Z0-9]+)*)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := jsJWTAlgorithmPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// bcrypt / bcryptjs
// ============================================================================

// bcryptHash detects bcrypt.hash(password, saltRounds) and bcrypt.genSalt(rounds).
func bcryptHash(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-bcrypt-hash",
		Language:  lang,
		Bundle:    "JSBcrypt",
		Pattern:   regexp.MustCompile(`\bbcrypt(?:js)?\s*\.\s*(?:hash|hashSync|genSalt|genSaltSync)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// argon2 (npm)
// ============================================================================

// argon2Hash detects argon2.hash(password, { type: argon2.argon2id }).
func argon2Hash(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-argon2-hash",
		Language:  lang,
		Bundle:    "JSArgon2",
		Pattern:   regexp.MustCompile(`\bargon2\s*\.\s*(?:hash|hashRaw|verify)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			// Try to capture variant from the same line
			name := "Argon2"
			variantMatch := regexp.MustCompile(`argon2\s*\.\s*(argon2id|argon2i|argon2d)`).FindStringSubmatch(match[0])
			if len(variantMatch) >= 2 {
				name = strings.Title(variantMatch[1]) //nolint:staticcheck
			}
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// crypto-js
// ============================================================================

// cryptoJSAlgo detects CryptoJS.AES.encrypt(...), CryptoJS.SHA256(...), CryptoJS.MD5(...), etc.
func cryptoJSAlgo(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-cryptojs-algo",
		Language:  lang,
		Bundle:    "CryptoJS",
		Pattern:   regexp.MustCompile(`CryptoJS\s*\.\s*(AES|DES|TripleDES|RC4|Rabbit|SHA1|SHA256|SHA512|SHA3|MD5|RIPEMD160)\s*\.`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := classifyCryptoJSPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			switch prim {
			case model.PrimitiveHash:
				algo.AddFunction(model.FuncDigest)
			default:
				algo.AddFunction(model.FuncEncrypt)
				algo.AddFunction(model.FuncDecrypt)
			}
			return []model.INode{algo}
		},
	}
}

// cryptoJSHmac detects CryptoJS.HmacSHA256(...), CryptoJS.HmacSHA512(...), etc.
func cryptoJSHmac(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-cryptojs-hmac",
		Language:  lang,
		Bundle:    "CryptoJS",
		Pattern:   regexp.MustCompile(`CryptoJS\s*\.\s*Hmac(SHA1|SHA256|SHA512|SHA3|MD5)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := "HMAC-" + match[1]
			algo := model.NewAlgorithm(name, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// tweetnacl
// ============================================================================

func naclSecretbox(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-nacl-secretbox",
		Language:  lang,
		Bundle:    "TweetNaCl",
		Pattern:   regexp.MustCompile(`\bnacl\s*\.\s*secretbox\s*[\.(]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NaCl/secretbox", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func naclBox(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-nacl-box",
		Language:  lang,
		Bundle:    "TweetNaCl",
		Pattern:   regexp.MustCompile(`\bnacl\s*\.\s*box\s*[\.(]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NaCl/box", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func naclSign(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-nacl-sign",
		Language:  lang,
		Bundle:    "TweetNaCl",
		Pattern:   regexp.MustCompile(`\bnacl\s*\.\s*sign\s*[\.(]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// node-forge
// ============================================================================

// forgeCipher detects forge.aes.createEncryptionCipher(...), forge.des.createEncryptionCipher(...), etc.
func forgeCipher(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-forge-cipher",
		Language:  lang,
		Bundle:    "NodeForge",
		Pattern:   regexp.MustCompile(`forge\s*\.\s*(aes|des|rc2|rc4|blowfish)\s*\.\s*create(?:Encryption|Decryption)?Cipher\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
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

// forgeDigest detects forge.md.sha256.create(), forge.md.sha512.create(), forge.md.md5.create(), etc.
func forgeDigest(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-forge-digest",
		Language:  lang,
		Bundle:    "NodeForge",
		Pattern:   regexp.MustCompile(`forge\s*\.\s*md\s*\.\s*(sha1|sha256|sha384|sha512|md5)\s*\.\s*create\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeForgeHash(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// forgePKI detects forge.pki.rsa.generateKeyPair(...), forge.pki.ed25519.generateKeyPair(...), etc.
func forgePKI(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-forge-pki",
		Language:  lang,
		Bundle:    "NodeForge",
		Pattern:   regexp.MustCompile(`forge\s*\.\s*pki\s*\.\s*(rsa|ed25519|dh)\s*\.\s*generateKeyPair\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.ToUpper(match[1])
			prim := classifyJSAsymmetricPrimitive(name)
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

// ============================================================================
// Helper functions
// ============================================================================

// extractNodeCipherAlgo parses Node.js cipher strings like 'aes-256-cbc', 'aes-128-gcm'.
// The algorithm node is named with the BASE cipher name (e.g. "AES", "DES", "3DES")
// so that vulnerability rules that match on name fire correctly. Mode and key length
// are attached as child nodes, mirroring the Java JCA pattern.
func extractNodeCipherAlgo(raw string, loc model.DetectionLocation, encrypt bool) []model.INode {
	upper := strings.ToUpper(raw) // e.g. AES-256-CBC
	parts := strings.Split(upper, "-")
	if len(parts) == 0 {
		return nil
	}

	// Derive the canonical base algorithm name.
	algoName := parts[0]
	switch {
	case algoName == "DES" && len(parts) > 1 && (parts[1] == "EDE3" || parts[1] == "EDE"):
		// des-ede3-cbc / des-ede-cbc → Triple-DES
		algoName = "3DES"
	case algoName == "BF":
		// OpenSSL short-form for Blowfish
		algoName = "Blowfish"
	case algoName == "CAMELLIA":
		algoName = "Camellia"
	}

	prim := classifyNodeCipherPrimitive(upper)
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

	// Extract mode from the last segment (CBC, GCM, CTR, ECB, …).
	if len(parts) >= 3 {
		mode := parts[len(parts)-1]
		if isKnownMode(mode) {
			algo.Put(model.NewMode(mode))
		}
	}
	return []model.INode{algo}
}

func classifyNodeCipherPrimitive(upper string) model.Primitive {
	switch {
	case strings.Contains(upper, "GCM") || strings.Contains(upper, "CCM") || strings.Contains(upper, "OCB"):
		return model.PrimitiveAEAD
	case strings.Contains(upper, "CHACHA20"):
		return model.PrimitiveStreamCipher
	case strings.Contains(upper, "RC4") || strings.Contains(upper, "ARC4"):
		return model.PrimitiveStreamCipher
	default:
		return model.PrimitiveBlockCipher
	}
}

func isKnownMode(m string) bool {
	switch m {
	case "CBC", "GCM", "CTR", "CFB", "OFB", "ECB", "CCM", "OCB", "SIV", "EAX":
		return true
	}
	return false
}

func classifyWebCryptoAlgo(name string) (string, model.Primitive) {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "AES-GCM"), strings.Contains(upper, "AES-CCM"):
		return name, model.PrimitiveAEAD
	case strings.Contains(upper, "AES"):
		return name, model.PrimitiveBlockCipher
	case strings.Contains(upper, "RSA-OAEP"), strings.Contains(upper, "RSA-PSS"),
		strings.Contains(upper, "RSASSA"):
		return name, model.PrimitiveSignature
	case strings.Contains(upper, "ECDSA"), strings.Contains(upper, "ECDH"):
		return name, model.PrimitiveSignature
	case strings.Contains(upper, "HMAC"):
		return name, model.PrimitiveMAC
	case strings.Contains(upper, "PBKDF2"):
		return name, model.PrimitivePasswordHash
	case strings.Contains(upper, "HKDF"):
		return name, model.PrimitiveKeyDerivation
	case strings.Contains(upper, "ED25519"):
		return name, model.PrimitiveSignature
	default:
		return name, model.PrimitiveUnknown
	}
}

func classifyJSAsymmetricPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "RSA"):
		return model.PrimitivePublicKeyEncryption
	case strings.Contains(upper, "EC"), strings.Contains(upper, "ECDSA"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "ED25519"), strings.Contains(upper, "ED448"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "DH"), strings.Contains(upper, "ECDH"):
		return model.PrimitiveKeyAgreement
	default:
		return model.PrimitiveUnknown
	}
}

func classifyCryptoJSPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case upper == "AES", upper == "DES", upper == "TRIPLEDES", upper == "RC4",
		upper == "RABBIT", upper == "RC2", upper == "BLOWFISH":
		return model.PrimitiveBlockCipher
	case upper == "SHA1", upper == "SHA256", upper == "SHA512", upper == "SHA3",
		upper == "MD5", upper == "RIPEMD160":
		return model.PrimitiveHash
	default:
		return model.PrimitiveUnknown
	}
}

func jsJWTAlgorithmPrimitive(alg string) model.Primitive {
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

func normalizeForgeHash(name string) string {
	switch strings.ToLower(name) {
	case "md5":
		return "MD5"
	case "sha1":
		return "SHA-1"
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

// jwtNoneAlgorithm detects the dangerous jwt.sign({}, key, {algorithm: 'none'})
// pattern that disables signature verification.
func jwtNoneAlgorithm(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-jwt-none",
		Language:  lang,
		Bundle:    "JSJWT",
		Pattern:   regexp.MustCompile(`(?i)\bjwt\.sign\s*\([^)]*algorithm\s*:\s*['"]none['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("none", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// nodeTLSCiphers detects the ciphers option in tls.createServer / https.createServer
// so that the cipher string itself is recorded as a detected asset.
func nodeTLSCiphers(lang detection.Language) *detection.Rule {
	return &detection.Rule{
		ID:        "js-tls-ciphers",
		Language:  lang,
		Bundle:    "NodeCrypto",
		Pattern:   regexp.MustCompile(`\bciphers\s*:\s*['"]([^'"]+)['"]`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			// Cipher string may be a colon-separated list (OpenSSL style).
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
