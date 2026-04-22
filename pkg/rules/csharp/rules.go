package csharp

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterCSharpDetectionRules registers all C# cryptography detection rules.
// Rules are grouped by source:
//   - System.Security.Cryptography — AES, DES, RSA, ECDsa, SHA*, HMAC, PBKDF2, RNG
//   - SslStream                    — TLS channel
//   - System.IdentityModel.Tokens.Jwt — JWT
//   - BouncyCastle .NET            — Org.BouncyCastle.*
func RegisterCSharpDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allCSharpRules() {
		registry.Register(r)
	}
}

func allCSharpRules() []*detection.Rule {
	return []*detection.Rule{
		// ── Symmetric ciphers: factory methods ───────────────────────────────
		csAesCreate(),
		csAesGcm(),
		csDesCreate(),
		csTripleDesCreate(),
		csRC2Create(),
		csAesCryptoServiceProvider(),
		csAesCng(),
		csRijndaelManaged(),
		// ── Cipher mode property ─────────────────────────────────────────────
		csCipherMode(),
		// ── Hash algorithms ───────────────────────────────────────────────────
		csSHA256Create(),
		csSHA512Create(),
		csSHA1Create(),
		csSHA384Create(),
		csMD5Create(),
		// ── SHA3 (.NET 8+) ───────────────────────────────────────────────────
		csSHA3Create(),
		// ── HMAC ─────────────────────────────────────────────────────────────
		csHMACNew(),
		// ── Asymmetric: RSA ───────────────────────────────────────────────────
		csRSACreate(),
		csRSACreateWithSize(),
		// ── Asymmetric: DSA ───────────────────────────────────────────────────
		csDSACreate(),
		// ── Asymmetric: ECDsa / ECDiffieHellman ───────────────────────────────
		csECDsaCreate(),
		csECDiffieHellmanCreate(),
		// ── Key derivation ────────────────────────────────────────────────────
		csRfc2898DeriveBytes(),
		// ── CSPRNG ────────────────────────────────────────────────────────────
		csRandomNumberGenerator(),
		// ── TLS via SslStream ─────────────────────────────────────────────────
		csSslStream(),
		csSslAuthenticate(),
		// ── JWT ───────────────────────────────────────────────────────────────
		csJwtSecurityToken(),
		csSecurityAlgorithms(),
		// ── BouncyCastle .NET ─────────────────────────────────────────────────
		csBCBlockCipherEngine(),
		csBCDigest(),
		csBCMac(),
		csBCSigner(),
		csBCKeyPairGenerator(),
		csBCPBEGenerator(),
	}
}

// ============================================================================
// Symmetric ciphers
// ============================================================================

func csAesCreate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-aes-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bAes\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// csAesGcm detects new AesGcm(key) — authenticated encryption added in .NET Core 3.
func csAesGcm() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-aesgcm-new",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`new\s+AesGcm\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES-GCM", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("GCM"))
			return []model.INode{algo}
		},
	}
}

func csDesCreate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-des-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bDES\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func csTripleDesCreate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-tripledes-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bTripleDES\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("3DES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func csRC2Create() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-rc2-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bRC2\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RC2", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func csAesCryptoServiceProvider() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-aes-csp",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`new\s+AesCryptoServiceProvider\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func csAesCng() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-aes-cng",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`new\s+AesCng\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func csRijndaelManaged() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-rijndael-managed",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`new\s+RijndaelManaged\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Rijndael", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// csCipherMode detects .Mode = CipherMode.ECB, .Mode = CipherMode.CBC, etc.
func csCipherMode() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-ciphermode",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`CipherMode\s*\.\s*(ECB|CBC|CFB|OFB|CTS|GCM)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			algo.Put(model.NewMode(match[1]))
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Hash algorithms
// ============================================================================

func csSHA256Create() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-sha256-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bSHA256\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SHA-256", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func csSHA512Create() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-sha512-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bSHA512\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SHA-512", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func csSHA384Create() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-sha384-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bSHA384\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SHA-384", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func csSHA1Create() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-sha1-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bSHA1\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SHA-1", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func csMD5Create() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-md5-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bMD5\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("MD5", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// HMAC
// ============================================================================

// csHMACNew detects new HMACSHA256(key), new HMACSHA512(key), new HMACMD5(key), etc.
func csHMACNew() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-hmac-new",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`new\s+HMAC(SHA1|SHA256|SHA384|SHA512|SHA3_256|SHA3_512|MD5|RIPEMD160)\s*\(`),
		MatchType: detection.MatchConstructor,
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
// Asymmetric: RSA
// ============================================================================

func csRSACreate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-rsa-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bRSA\s*\.\s*Create\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			pubKey := model.NewKey("RSA", model.KindPublicKey, loc)
			pubKey.Put(algo)
			privKey := model.NewKey("RSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{pubKey, privKey}
		},
	}
}

// csRSACreateWithSize detects RSA.Create(2048) — key size as argument.
func csRSACreateWithSize() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-rsa-create-size",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bRSA\s*\.\s*Create\s*\(\s*(\d+)\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			if len(match) >= 2 {
				if bits, err := strconv.Atoi(match[1]); err == nil {
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

// ============================================================================
// Asymmetric: ECDsa / ECDiffieHellman
// ============================================================================

func csECDsaCreate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-ecdsa-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bECDsa\s*\.\s*Create\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			pubKey := model.NewKey("ECDSA", model.KindPublicKey, loc)
			pubKey.Put(algo)
			privKey := model.NewKey("ECDSA", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{pubKey, privKey}
		},
	}
}

func csECDiffieHellmanCreate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-ecdh-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\bECDiffieHellman\s*\.\s*Create\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDH", model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Key derivation: PBKDF2 (Rfc2898DeriveBytes)
// ============================================================================

func csRfc2898DeriveBytes() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-pbkdf2-rfc2898",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`new\s+Rfc2898DeriveBytes\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PBKDF2", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// CSPRNG
// ============================================================================

func csRandomNumberGenerator() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-rng",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`RandomNumberGenerator\s*\.\s*(?:Create|GetBytes|GetInt32|Fill)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RandomNumberGenerator", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// TLS via SslStream
// ============================================================================

func csSslStream() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-sslstream-new",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetTLS",
		Pattern:   regexp.MustCompile(`new\s+SslStream\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

func csSslAuthenticate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-sslstream-authenticate",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetTLS",
		Pattern:   regexp.MustCompile(`\.AuthenticateAs(?:Client|Server)(?:Async)?\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

// ============================================================================
// JWT (System.IdentityModel.Tokens.Jwt / Microsoft.IdentityModel.Tokens)
// ============================================================================

func csJwtSecurityToken() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-jwt-securitytoken",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetJWT",
		Pattern:   regexp.MustCompile(`new\s+JwtSecurityToken\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("JWT", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// csSecurityAlgorithms detects SecurityAlgorithms.HmacSha256, SecurityAlgorithms.RsaSha256, etc.
func csSecurityAlgorithms() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-security-algorithms",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetJWT",
		Pattern:   regexp.MustCompile(`SecurityAlgorithms\s*\.\s*(HmacSha\d+|RsaSha\d+|RsaSsaPss\w*|EcdsaSha\d+|Aes\d+\w*)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := classifyCSAlgorithmName(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// BouncyCastle .NET (Org.BouncyCastle.*)
// ============================================================================

func csBCBlockCipherEngine() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-bc-block-cipher",
		Language:  detection.LangCSharp,
		Bundle:    "BCDotNet",
		Pattern:   regexp.MustCompile(`new\s+(Aes|Des|DesEde|Blowfish|Twofish|Camellia|Aria|Sm4|Cast5|Cast6|Idea|Rc2|Seed|Serpent|Skipjack|Tea|Xtea)Engine\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func csBCDigest() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-bc-digest",
		Language:  detection.LangCSharp,
		Bundle:    "BCDotNet",
		Pattern:   regexp.MustCompile(`new\s+(Sha\d+|Sha3|Md5|Md4|Md2|RipeMD\d+|Whirlpool|Tiger|Blake2b|Blake2s|Sm3|Keccak)\w*Digest\s*\(`),
		MatchType: detection.MatchConstructor,
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

func csBCMac() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-bc-mac",
		Language:  detection.LangCSharp,
		Bundle:    "BCDotNet",
		Pattern:   regexp.MustCompile(`new\s+(HMac|CMac|GMac|Poly1305|SipHash|Kmac)\s*\(`),
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

func csBCSigner() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-bc-signer",
		Language:  detection.LangCSharp,
		Bundle:    "BCDotNet",
		Pattern:   regexp.MustCompile(`new\s+(RsaDigestSigner|ECDsaSigner|Ed25519Signer|DsaSigner|Sm2Signer)\s*\(`),
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

func csBCKeyPairGenerator() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-bc-keypairgen",
		Language:  detection.LangCSharp,
		Bundle:    "BCDotNet",
		Pattern:   regexp.MustCompile(`new\s+(RsaKeyPairGenerator|ECKeyPairGenerator|DsaKeyPairGenerator|Ed25519KeyPairGenerator|DhKeyPairGenerator)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := strings.TrimSuffix(match[1], "KeyPairGenerator")
			prim := classifyCSBCAsymmetricPrimitive(name)
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

func csBCPBEGenerator() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-bc-pbe",
		Language:  detection.LangCSharp,
		Bundle:    "BCDotNet",
		Pattern:   regexp.MustCompile(`new\s+(Pkcs5S2ParametersGenerator|Pkcs12ParametersGenerator|SCryptParametersGenerator|Argon2BytesGenerator)\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			nameMap := map[string]string{
				"Pkcs5S2ParametersGenerator":  "PBKDF2",
				"Pkcs12ParametersGenerator":   "PKCS12-PBE",
				"SCryptParametersGenerator":   "scrypt",
				"Argon2BytesGenerator":        "Argon2",
			}
			name, ok := nameMap[match[1]]
			if !ok {
				name = match[1]
			}
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// DSA
// ============================================================================

func csDSACreate() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-dsa-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`(?:DSA\.Create|new\s+DSACryptoServiceProvider|new\s+DSACng)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			key := model.NewKey("DSA", model.KindPrivateKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// ============================================================================
// SHA3 (.NET 8+)
// ============================================================================

func csSHA3Create() *detection.Rule {
	return &detection.Rule{
		ID:        "cs-sha3-create",
		Language:  detection.LangCSharp,
		Bundle:    "DotNetCrypto",
		Pattern:   regexp.MustCompile(`\b(SHA3_256|SHA3_512|Shake128|Shake256)\s*\.\s*Create\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			nameMap := map[string]string{
				"SHA3_256": "SHA3-256",
				"SHA3_512": "SHA3-512",
				"Shake128": "SHAKE128",
				"Shake256": "SHAKE256",
			}
			name, ok := nameMap[match[1]]
			if !ok {
				name = match[1]
			}
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func classifyCSAlgorithmName(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.HasPrefix(upper, "HMAC"):
		return model.PrimitiveMAC
	case strings.Contains(upper, "RSA"), strings.Contains(upper, "ECDSA"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "AES"):
		return model.PrimitiveBlockCipher
	default:
		return model.PrimitiveUnknown
	}
}

func classifyCSBCAsymmetricPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "RSA"):
		return model.PrimitivePublicKeyEncryption
	case strings.Contains(upper, "EC"), strings.Contains(upper, "DSA"),
		strings.Contains(upper, "ED25519"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "DH"):
		return model.PrimitiveKeyAgreement
	default:
		return model.PrimitiveUnknown
	}
}
