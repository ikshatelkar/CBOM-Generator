package golang

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterGoDetectionRules registers all Go cryptography detection rules.
// Rules are grouped by source:
//   - Go stdlib (crypto/*)   — aes, des, rc4, rsa, ecdsa, ed25519, sha*, hmac, tls, rand
//   - golang.org/x/crypto    — chacha20poly1305, argon2, bcrypt, pbkdf2, scrypt, blake2, nacl, hkdf
//   - JWT libraries          — github.com/golang-jwt/jwt, github.com/dgrijalva/jwt-go
func RegisterGoDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range allGoRules() {
		registry.Register(r)
	}
}

func allGoRules() []*detection.Rule {
	return []*detection.Rule{
		// ── Symmetric block ciphers ───────────────────────────────────────────
		goAESNewCipher(),
		goDESNewCipher(),
		goTripleDESNewCipher(),
		goRC4NewCipher(),
		// ── Cipher modes ─────────────────────────────────────────────────────
		goCipherNewGCM(),
		goCipherNewCBC(),
		goCipherNewCFB(),
		goCipherNewOFB(),
		goCipherNewCTR(),
		// ── Hash functions ────────────────────────────────────────────────────
		goMD5(),
		goSHA1(),
		goSHA256(),
		goSHA512(),
		// ── SHA3 (golang.org/x/crypto/sha3) ─────────────────────────────────
		goSHA3(),
		// ── HMAC ─────────────────────────────────────────────────────────────
		goHMACNew(),
		// ── Asymmetric: RSA ───────────────────────────────────────────────────
		goRSAGenerateKey(),
		goRSAEncrypt(),
		goRSADecrypt(),
		goRSASign(),
		goRSAVerify(),
		// ── Asymmetric: ECDSA / elliptic curves ───────────────────────────────
		goECDSAGenerateKey(),
		goECDSASign(),
		goECDSAVerify(),
		goEllipticCurve(),
		// ── Asymmetric: ECDH (crypto/ecdh — Go 1.20+) ────────────────────────
		goECDH(),
		// ── Asymmetric: Ed25519 ───────────────────────────────────────────────
		goEd25519GenerateKey(),
		goEd25519Sign(),
		goEd25519Verify(),
		// ── Asymmetric: DSA (deprecated since Go 1.15) ────────────────────────
		goDSAGenerateKey(),
		// ── CSPRNG ────────────────────────────────────────────────────────────
		goCryptoRandRead(),
		// ── TLS ───────────────────────────────────────────────────────────────
		goTLSMinVersion(),
		goTLSDial(),
		goTLSListen(),
		goTLSCipherSuites(),
		goTLSCurvePreferences(),
		// ── Post-Quantum TLS (Go 1.23+ hybrid KEM) ───────────────────────────
		goX25519MLKEM768(),
		// ── golang.org/x/crypto ───────────────────────────────────────────────
		goChaCha20Poly1305(),
		goXChaCha20Poly1305(),
		goArgon2IDKey(),
		goArgon2Key(),
		goBcryptGenerate(),
		goPBKDF2Key(),
		goPBKDF2KeyGeneric(),
		goScryptKey(),
		goBlake2b(),
		goBlake2s(),
		goNaClBoxGenerateKey(),
		goNaClBoxSeal(),
		goNaClSecretboxSeal(),
		goHKDFNew(),
		goCurve25519X25519(),
		goChaCha20Unauthenticated(),
		// ── JWT libraries ─────────────────────────────────────────────────────
		goJWTNewWithClaims(),
		goJWTSigningMethod(),
		// ── Shamir's Secret Sharing (hashicorp/vault/shamir) ──────────────────
		goShamirSplit(),
		// ── OTP (github.com/pquerna/otp) ──────────────────────────────────────
		goTOTPGenerate(),
		goHOTPGenerate(),
		// ── AES-CMAC via Google Tink (tink-crypto/tink-go) ───────────────────
		goTinkAESCMAC(),
		// ── crypto/x509 — certificate and key operations ─────────────────────
		goX509CreateCertificate(),
		goX509ParseCertificate(),
		goX509ParsePKCS8PrivateKey(),
		goX509ParsePKCS1PrivateKey(),
		goX509ParseECPrivateKey(),
		goX509MarshalPrivateKey(),
		// ── crypto/tls — keypair loading ─────────────────────────────────────
		goTLSLoadX509KeyPair(),
		// ── math/rand — insecure PRNG (security finding) ─────────────────────
		goMathRandInsecure(),
	}
}

// ============================================================================
// Symmetric block ciphers
// ============================================================================

func goAESNewCipher() *detection.Rule {
	return &detection.Rule{
		ID:        "go-aes-newcipher",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\baes\.NewCipher\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func goDESNewCipher() *detection.Rule {
	return &detection.Rule{
		ID:        "go-des-newcipher",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bdes\.NewCipher\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func goTripleDESNewCipher() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tripledes-newcipher",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`des\.NewTripleDESCipher\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("3DES", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func goRC4NewCipher() *detection.Rule {
	return &detection.Rule{
		ID:        "go-rc4-newcipher",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\brc4\.NewCipher\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RC4", model.PrimitiveStreamCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Cipher modes (crypto/cipher)
// ============================================================================

func goCipherNewGCM() *detection.Rule {
	return &detection.Rule{
		ID:        "go-cipher-gcm",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`cipher\.NewGCM(?:WithNonceSize|WithTagSize)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES-GCM", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("GCM"))
			return []model.INode{algo}
		},
	}
}

func goCipherNewCBC() *detection.Rule {
	return &detection.Rule{
		ID:        "go-cipher-cbc",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`cipher\.NewCBC(?:Encrypter|Decrypter)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			// cipher.NewCBCEncrypter wraps ANY block cipher (AES, DES, 3DES…).
			// Name the mode only; the block cipher is detected by its own rule.
			algo := model.NewAlgorithm("CBC", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("CBC"))
			return []model.INode{algo}
		},
	}
}

func goCipherNewCFB() *detection.Rule {
	return &detection.Rule{
		ID:        "go-cipher-cfb",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`cipher\.NewCFB(?:Encrypter|Decrypter)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			// cipher.NewCFBEncrypter wraps ANY block cipher.
			algo := model.NewAlgorithm("CFB", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("CFB"))
			return []model.INode{algo}
		},
	}
}

func goCipherNewOFB() *detection.Rule {
	return &detection.Rule{
		ID:        "go-cipher-ofb",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`cipher\.NewOFB\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			// cipher.NewOFB wraps ANY block cipher.
			algo := model.NewAlgorithm("OFB", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("OFB"))
			return []model.INode{algo}
		},
	}
}

func goCipherNewCTR() *detection.Rule {
	return &detection.Rule{
		ID:        "go-cipher-ctr",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`cipher\.NewCTR\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			// cipher.NewCTR wraps ANY block cipher.
			algo := model.NewAlgorithm("CTR", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			algo.Put(model.NewMode("CTR"))
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Hash functions
// ============================================================================

func goMD5() *detection.Rule {
	return &detection.Rule{
		ID:        "go-md5",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bmd5\.(?:New|Sum)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("MD5", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func goSHA1() *detection.Rule {
	return &detection.Rule{
		ID:        "go-sha1",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bsha1\.(?:New|Sum)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SHA-1", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func goSHA256() *detection.Rule {
	return &detection.Rule{
		ID:        "go-sha256",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bsha256\.(?:New(?:224)?|Sum(?:224|256))\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "SHA-256"
			if strings.Contains(match[0], "224") {
				name = "SHA-224"
			}
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func goSHA512() *detection.Rule {
	return &detection.Rule{
		ID:        "go-sha512",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bsha512\.(?:New(?:384|512_224|512_256)?|Sum(?:384|512|512_224|512_256))\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "SHA-512"
			switch {
			case strings.Contains(match[0], "512_224"):
				name = "SHA-512/224"
			case strings.Contains(match[0], "512_256"):
				name = "SHA-512/256"
			case strings.Contains(match[0], "384"):
				name = "SHA-384"
			}
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// HMAC
// ============================================================================

// goHMACNew detects hmac.New(sha256.New, key) and captures the underlying hash.
func goHMACNew() *detection.Rule {
	return &detection.Rule{
		ID:        "go-hmac-new",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bhmac\.New\s*\(\s*(sha\d+|md5|sha1)\.New`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			hash := normalizeGoHash(match[1])
			algo := model.NewAlgorithm("HMAC-"+hash, model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

func normalizeGoHash(pkg string) string {
	switch strings.ToLower(pkg) {
	case "md5":
		return "MD5"
	case "sha1":
		return "SHA-1"
	case "sha256":
		return "SHA-256"
	case "sha512":
		return "SHA-512"
	default:
		return strings.ToUpper(pkg)
	}
}

// ============================================================================
// Asymmetric: RSA
// ============================================================================

// goRSAGenerateKey detects rsa.GenerateKey(rand.Reader, 2048) and captures key size.
func goRSAGenerateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-rsa-generatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`rsa\.GenerateKey\s*\([^,]+,\s*(\d+)\s*\)`),
		MatchType: detection.MatchFunctionCall,
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

func goRSAEncrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "go-rsa-encrypt",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`rsa\.Encrypt(PKCS1v15|OAEP)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("RSA-"+match[1], model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncEncrypt)
			return []model.INode{algo}
		},
	}
}

func goRSADecrypt() *detection.Rule {
	return &detection.Rule{
		ID:        "go-rsa-decrypt",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`rsa\.Decrypt(PKCS1v15|OAEP)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("RSA-"+match[1], model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func goRSASign() *detection.Rule {
	return &detection.Rule{
		ID:        "go-rsa-sign",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`rsa\.Sign(PKCS1v15|PSS)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("RSA-"+match[1], model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func goRSAVerify() *detection.Rule {
	return &detection.Rule{
		ID:        "go-rsa-verify",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`rsa\.Verify(PKCS1v15|PSS)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("RSA-"+match[1], model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Asymmetric: ECDSA / elliptic curves
// ============================================================================

// goECDSAGenerateKey captures ecdsa.GenerateKey(elliptic.P256(), rand.Reader).
func goECDSAGenerateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-ecdsa-generatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`ecdsa\.GenerateKey\s*\(\s*elliptic\.(P\d+)\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			curve := "P-256"
			if len(match) >= 2 {
				// P256 → P-256, P384 → P-384, P521 → P-521
				raw := match[1]
				curve = raw[:1] + "-" + raw[1:]
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

func goECDSASign() *detection.Rule {
	return &detection.Rule{
		ID:        "go-ecdsa-sign",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\becdsa\.Sign\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func goECDSAVerify() *detection.Rule {
	return &detection.Rule{
		ID:        "go-ecdsa-verify",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\becdsa\.Verify\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// goEllipticCurve detects standalone elliptic curve references like elliptic.P256().
func goEllipticCurve() *detection.Rule {
	return &detection.Rule{
		ID:        "go-elliptic-curve",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`elliptic\.(P224|P256|P384|P521)\s*\(\s*\)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			raw := match[1]                   // e.g. P256
			name := raw[:1] + "-" + raw[1:]   // → P-256
			algo := model.NewAlgorithm(name, model.PrimitiveSignature, loc)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Asymmetric: Ed25519
// ============================================================================

func goEd25519GenerateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-ed25519-generatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bed25519\.GenerateKey\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			pubKey := model.NewKey("Ed25519", model.KindPublicKey, loc)
			pubKey.Put(algo)
			privKey := model.NewKey("Ed25519", model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{pubKey, privKey}
		},
	}
}

func goEd25519Sign() *detection.Rule {
	return &detection.Rule{
		ID:        "go-ed25519-sign",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bed25519\.Sign\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func goEd25519Verify() *detection.Rule {
	return &detection.Rule{
		ID:        "go-ed25519-verify",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bed25519\.Verify\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Ed25519", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Asymmetric: DSA (deprecated in Go 1.15+)
// ============================================================================

func goDSAGenerateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-dsa-generatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bdsa\.GenerateKey\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("DSA", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// CSPRNG (crypto/rand)
// ============================================================================

func goCryptoRandRead() *detection.Rule {
	return &detection.Rule{
		ID:        "go-crypto-rand-read",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\brand\.(?:Read|Int|Prime|Text)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("crypto/rand", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// TLS (crypto/tls)
// ============================================================================

// goTLSMinVersion detects MinVersion: tls.VersionTLS12 in tls.Config struct literals.
func goTLSMinVersion() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tls-minversion",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`MinVersion\s*:\s*(tls\.Version\w+)`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			version := normalizeTLSVersion(match[1])
			proto := model.NewProtocol(version, loc)
			return []model.INode{proto}
		},
	}
}

func goTLSDial() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tls-dial",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\btls\.(?:Dial|DialWithDialer|Client)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

func goTLSListen() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tls-listen",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\btls\.(?:Listen|NewListener|Server)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			return []model.INode{model.NewProtocol("TLS", loc)}
		},
	}
}

func normalizeTLSVersion(constant string) string {
	switch {
	case strings.Contains(constant, "TLS10"):
		return "TLSv1.0"
	case strings.Contains(constant, "TLS11"):
		return "TLSv1.1"
	case strings.Contains(constant, "TLS12"):
		return "TLSv1.2"
	case strings.Contains(constant, "TLS13"):
		return "TLSv1.3"
	case strings.Contains(constant, "SSL30"):
		return "SSLv3.0"
	default:
		return "TLS"
	}
}

// ============================================================================
// golang.org/x/crypto — ChaCha20-Poly1305
// ============================================================================

func goChaCha20Poly1305() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-chacha20poly1305",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bchacha20poly1305\.New\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ChaCha20-Poly1305", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func goXChaCha20Poly1305() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-xchacha20poly1305",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bchacha20poly1305\.NewX\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("XChaCha20-Poly1305", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — Argon2
// ============================================================================

func goArgon2IDKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-argon2id",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bargon2\.IDKey\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Argon2id", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func goArgon2Key() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-argon2i",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bargon2\.Key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Argon2i", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — bcrypt
// ============================================================================

func goBcryptGenerate() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-bcrypt",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bbcrypt\.(?:GenerateFromPassword|CompareHashAndPassword)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — PBKDF2
// ============================================================================

func goPBKDF2Key() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-pbkdf2",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		// Capture the hash constructor (5th argument): pbkdf2.Key(pass, salt, iter, len, sha1.New)
		Pattern:   regexp.MustCompile(`\bpbkdf2\.Key\s*\([^,]*,[^,]*,[^,]*,[^,]*,\s*(sha\w+|md5)\s*\.New`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			hashName := "SHA256"
			if len(match) >= 2 {
				hashName = normalizeGoHashPackageName(match[1])
			}
			name := "PBKDF2WithHmac" + strings.ReplaceAll(hashName, "-", "")
			algo := model.NewAlgorithm(name, model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

func goPBKDF2KeyGeneric() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-pbkdf2-generic",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bpbkdf2\.Key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PBKDF2", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — scrypt
// ============================================================================

func goScryptKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-scrypt",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bscrypt\.Key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("scrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — BLAKE2
// ============================================================================

func goBlake2b() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-blake2b",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bblake2b\.(?:New(?:256|512|384)?|Sum(?:256|512))\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			name := "BLAKE2b-512"
			switch {
			case strings.Contains(match[0], "256"):
				name = "BLAKE2b-256"
			case strings.Contains(match[0], "384"):
				name = "BLAKE2b-384"
			}
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func goBlake2s() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-blake2s",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bblake2s\.(?:New256|Sum256)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("BLAKE2s-256", model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — NaCl box / secretbox
// ============================================================================

func goNaClBoxGenerateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-nacl-box-generatekey",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bbox\.GenerateKey\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NaCl/box", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncKeyGen)
			pubKey := model.NewKey("Curve25519", model.KindPublicKey, loc)
			privKey := model.NewKey("Curve25519", model.KindPrivateKey, loc)
			return []model.INode{algo, pubKey, privKey}
		},
	}
}

func goNaClBoxSeal() *detection.Rule {
	return &detection.Rule{
		ID:        "go-nacl-box-seal",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bbox\.(?:Seal|Open|SealAfterPrecomputation|OpenAfterPrecomputation)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NaCl/box", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

func goNaClSecretboxSeal() *detection.Rule {
	return &detection.Rule{
		ID:        "go-nacl-secretbox",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bsecretbox\.(?:Seal|Open)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NaCl/secretbox", model.PrimitiveAEAD, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — HKDF
// ============================================================================

func goHKDFNew() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-hkdf",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bhkdf\.(?:New|Extract|Expand)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HKDF", model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — Curve25519 / X25519
// ============================================================================

func goCurve25519X25519() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-x25519",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bcurve25519\.(?:X25519|ScalarMult|ScalarBaseMult)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X25519", model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// golang.org/x/crypto — ChaCha20 (unauthenticated stream cipher)
// ============================================================================

// goChaCha20Unauthenticated detects the raw ChaCha20 stream cipher without Poly1305.
// Using it directly without authentication is a security risk (no integrity protection).
func goChaCha20Unauthenticated() *detection.Rule {
	return &detection.Rule{
		ID:        "go-xcrypto-chacha20-stream",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`chacha20\.NewUnauthenticatedCipher\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ChaCha20", model.PrimitiveStreamCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// JWT libraries (github.com/golang-jwt/jwt, github.com/dgrijalva/jwt-go)
// ============================================================================

// goJWTNewWithClaims detects jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
func goJWTNewWithClaims() *detection.Rule {
	return &detection.Rule{
		ID:        "go-jwt-newwithclaims",
		Language:  detection.LangGo,
		Bundle:    "GoJWT",
		Pattern:   regexp.MustCompile(`jwt\.NewWithClaims\s*\(\s*jwt\.SigningMethod(\w+)\s*,`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := jwtGoAlgorithmPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// goJWTSigningMethod detects bare jwt.SigningMethodXXX constant references.
func goJWTSigningMethod() *detection.Rule {
	return &detection.Rule{
		ID:        "go-jwt-signingmethod",
		Language:  detection.LangGo,
		Bundle:    "GoJWT",
		Pattern:   regexp.MustCompile(`\bjwt\.SigningMethod(HS256|HS384|HS512|RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|EdDSA|NONE|none)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := jwtGoAlgorithmPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

func jwtGoAlgorithmPrimitive(alg string) model.Primitive {
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

// ============================================================================
// SHA3 (golang.org/x/crypto/sha3)
// ============================================================================

func goSHA3() *detection.Rule {
	return &detection.Rule{
		ID:        "go-sha3",
		Language:  detection.LangGo,
		Bundle:    "GoXCrypto",
		Pattern:   regexp.MustCompile(`\bsha3\.(New(?:224|256|384|512)|Sum(?:224|256|384|512))\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			fn := ""
			if len(match) >= 2 {
				fn = match[1]
			}
			name := "SHA3-256"
			switch {
			case strings.HasSuffix(fn, "512"):
				name = "SHA3-512"
			case strings.HasSuffix(fn, "384"):
				name = "SHA3-384"
			case strings.HasSuffix(fn, "224"):
				name = "SHA3-224"
			}
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// ECDH (crypto/ecdh — Go 1.20+)
// ============================================================================

func goECDH() *detection.Rule {
	return &detection.Rule{
		ID:        "go-ecdh-generatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\becdh\.(P256|P384|P521|X25519)\s*\(\s*\)\s*\.\s*(?:GenerateKey|NewPrivateKey)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			raw := match[1]
			var curveName string
			if raw == "X25519" {
				curveName = "X25519"
			} else {
				// P256 → P-256, P384 → P-384, P521 → P-521
				curveName = raw[:1] + "-" + raw[1:]
			}
			algo := model.NewAlgorithm("ECDH", model.PrimitiveKeyAgreement, loc)
			algo.AddFunction(model.FuncKeyGen)
			algo.Put(model.NewEllipticCurve(curveName))
			key := model.NewKey("ECDH-"+curveName, model.KindPrivateKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// ============================================================================
// TLS cipher suites in tls.Config{CipherSuites: []uint16{...}}
// ============================================================================

func goTLSCipherSuites() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tls-ciphersuites",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`CipherSuites\s*:\s*\[\s*\]uint16\s*\{([^}]+)\}`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			suiteRe := regexp.MustCompile(`tls\.(TLS_[A-Z0-9_]+)`)
			suites := suiteRe.FindAllStringSubmatch(match[1], -1)
			var nodes []model.INode
			for _, s := range suites {
				if len(s) >= 2 {
					nodes = append(nodes, model.NewCipherSuite(s[1], loc))
				}
			}
			return nodes
		},
	}
}

// normalizeGoHashPackageName maps Go hash package names (sha256, sha1, md5) to
// canonical algorithm names used in PBKDF2WithHmac naming.
func normalizeGoHashPackageName(pkg string) string {
	switch strings.ToLower(pkg) {
	case "sha1":
		return "SHA1"
	case "sha256":
		return "SHA256"
	case "sha512":
		return "SHA512"
	case "sha384":
		return "SHA384"
	case "md5":
		return "MD5"
	case "sha3_256":
		return "SHA3-256"
	case "sha3_512":
		return "SHA3-512"
	default:
		return strings.ToUpper(pkg)
	}
}

// ============================================================================
// TLS curve preferences (crypto/tls CurveID constants)
// ============================================================================

// goTLSCurvePreferences detects TLS curve preferences set in tls.Config, e.g.
// CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}.
func goTLSCurvePreferences() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tls-curve-preferences",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\btls\.(X25519|CurveP256|CurveP384|CurveP521)\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeTLSCurve(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveKeyAgreement, loc)
			algo.Put(model.NewEllipticCurve(name))
			return []model.INode{algo}
		},
	}
}

func normalizeTLSCurve(c string) string {
	switch c {
	case "X25519":
		return "X25519"
	case "CurveP256":
		return "P-256"
	case "CurveP384":
		return "P-384"
	case "CurveP521":
		return "P-521"
	default:
		return c
	}
}

// ============================================================================
// Post-Quantum TLS: X25519MLKEM768 hybrid KEM (Go 1.23+, tls.X25519MLKEM768)
// ============================================================================

// goX25519MLKEM768 detects the use of the Post-Quantum hybrid key exchange
// X25519MLKEM768 (X25519 + ML-KEM-768) introduced in Go 1.23.
// Used in tls.Config CurvePreferences or Caddy's SupportedCurves map.
func goX25519MLKEM768() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tls-x25519mlkem768",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\btls\.X25519MLKEM768\b`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X25519MLKEM768", model.PrimitiveKeyEncapsulation, loc)
			algo.AddFunction(model.FuncEncapsulate)
			algo.AddFunction(model.FuncDecapsulate)
			algo.Put(model.NewEllipticCurve("X25519"))
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// Shamir's Secret Sharing (github.com/hashicorp/vault/shamir)
// ============================================================================

// goShamirSplit detects calls to shamir.Split and shamir.Combine, which
// implement Shamir's Secret Sharing scheme for key splitting/reconstruction.
func goShamirSplit() *detection.Rule {
	return &detection.Rule{
		ID:        "go-shamir-split",
		Language:  detection.LangGo,
		Bundle:    "GoVault",
		Pattern:   regexp.MustCompile(`\bshamir\.(Split|Combine)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			fn := FuncShamirSplit
			if len(match) >= 2 && match[1] == "Combine" {
				fn = FuncShamirCombine
			}
			algo := model.NewAlgorithm("Shamir-Secret-Sharing", model.PrimitiveKeyDerivation, loc)
			algo.AddFunction(fn)
			return []model.INode{algo}
		},
	}
}

const (
	FuncShamirSplit   model.CryptoFunc = "split"
	FuncShamirCombine model.CryptoFunc = "combine"
)

// ============================================================================
// OTP: TOTP and HOTP (github.com/pquerna/otp)
// ============================================================================

// goTOTPGenerate detects TOTP code generation and validation calls from the
// pquerna/otp library, which implements RFC 6238 (TOTP = HMAC-based OTP).
func goTOTPGenerate() *detection.Rule {
	return &detection.Rule{
		ID:        "go-totp-generate",
		Language:  detection.LangGo,
		Bundle:    "GoOTP",
		Pattern:   regexp.MustCompile(`\btotp\.(Generate(?:WithCustomOptions)?|Validate(?:Custom)?|GenerateCode(?:WithCustomOptions)?|ValidateCustom)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("TOTP", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// goHOTPGenerate detects HOTP code generation and validation calls from the
// pquerna/otp library, which implements RFC 4226 (HOTP = HMAC-based OTP).
func goHOTPGenerate() *detection.Rule {
	return &detection.Rule{
		ID:        "go-hotp-generate",
		Language:  detection.LangGo,
		Bundle:    "GoOTP",
		Pattern:   regexp.MustCompile(`\bhotp\.(Generate(?:WithCustomOptions)?|Validate(?:Custom)?|GenerateCode(?:WithCustomOptions)?|ValidateCustom)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HOTP", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// AES-CMAC via Google Tink (github.com/tink-crypto/tink-go/v2/kwp/subtle)
// ============================================================================

// goTinkAESCMAC detects AES-CMAC construction via Google Tink's kwp/subtle
// package, used in Vault's transit secrets engine for CMAC key types.
func goTinkAESCMAC() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tink-aescmac",
		Language:  detection.LangGo,
		Bundle:    "GoTink",
		Pattern:   regexp.MustCompile(`\bsubtle\.NewAESCMAC\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("AES-CMAC", model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// crypto/x509 — certificate and key operations (any Go project)
// ============================================================================

// goX509CreateCertificate detects x509.CreateCertificate, used to generate
// self-signed or CA-signed X.509 certificates in any Go PKI tool or server.
func goX509CreateCertificate() *detection.Rule {
	return &detection.Rule{
		ID:        "go-x509-createcertificate",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bx509\.CreateCertificate(?:Request)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X.509", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

// goX509ParseCertificate detects x509.ParseCertificate and
// x509.ParseCertificates, used whenever TLS certificates are loaded or
// inspected at runtime in any Go application.
func goX509ParseCertificate() *detection.Rule {
	return &detection.Rule{
		ID:        "go-x509-parsecertificate",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bx509\.ParseCertificate(?:s|Request)?\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X.509", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// goX509ParsePKCS8PrivateKey detects parsing of PKCS#8-encoded private keys
// (RSA, ECDSA, Ed25519). Used in any Go app that loads private keys from PEM/DER.
func goX509ParsePKCS8PrivateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-x509-parsepkcs8privatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bx509\.ParsePKCS8PrivateKey\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			key := model.NewKey("PKCS8-PrivateKey", model.KindPrivateKey, loc)
			return []model.INode{key}
		},
	}
}

// goX509ParsePKCS1PrivateKey detects parsing of PKCS#1-encoded RSA private keys.
// Very common in any Go app loading RSA keys from PEM files.
func goX509ParsePKCS1PrivateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-x509-parsepkcs1privatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bx509\.ParsePKCS1(?:Private|Public)Key\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("RSA", model.PrimitivePublicKeyEncryption, loc)
			key := model.NewKey("RSA", model.KindPrivateKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// goX509ParseECPrivateKey detects parsing of SEC1-encoded EC private keys.
// Used in any Go TLS server or crypto tool loading elliptic curve keys.
func goX509ParseECPrivateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-x509-parseecprivatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bx509\.ParseECPrivateKey\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("ECDSA", model.PrimitiveSignature, loc)
			key := model.NewKey("ECDSA", model.KindPrivateKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// goX509MarshalPrivateKey detects marshaling of private keys to DER/PKCS#8 format.
// Covers MarshalPKCS8PrivateKey, MarshalPKCS1PrivateKey, MarshalECPrivateKey.
func goX509MarshalPrivateKey() *detection.Rule {
	return &detection.Rule{
		ID:        "go-x509-marshalprivatekey",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bx509\.Marshal(?:PKCS8PrivateKey|PKCS1(?:Private|Public)Key|ECPrivateKey|PKIX(?:PublicKey)?)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("X.509", model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncKeyGen)
			return []model.INode{algo}
		},
	}
}

// ============================================================================
// crypto/tls — keypair loading (any Go HTTPS server)
// ============================================================================

// goTLSLoadX509KeyPair detects tls.LoadX509KeyPair and tls.X509KeyPair, which
// load a certificate and private key for TLS in any Go HTTPS server or client.
func goTLSLoadX509KeyPair() *detection.Rule {
	return &detection.Rule{
		ID:        "go-tls-loadx509keypair",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\btls\.(?:LoadX509KeyPair|X509KeyPair)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			proto := model.NewProtocol("TLS", loc)
			key := model.NewKey("X.509", model.KindPublicKey, loc)
			return []model.INode{proto, key}
		},
	}
}

// ============================================================================
// math/rand — insecure PRNG (any Go project using non-cryptographic random)
// ============================================================================

// goMathRandInsecure detects usage of math/rand (non-cryptographic), which is
// a security risk when used for secrets, tokens, or cryptographic purposes.
//
// The pattern matches either the import path "math/rand" on import lines, OR
// calls to functions that are EXCLUSIVE to math/rand (not present in crypto/rand).
// This avoids false positives against crypto/rand.Read / crypto/rand.Int /
// crypto/rand.Prime / crypto/rand.Text, which are detected by go-crypto-rand-read.
func goMathRandInsecure() *detection.Rule {
	return &detection.Rule{
		ID:        "go-mathrand-insecure",
		Language:  detection.LangGo,
		Bundle:    "GoStdlib",
		Pattern:   regexp.MustCompile(`\bmath/rand\b|\brand\.(New|Seed|Intn|Int63n?|Int31n?|Float(?:32|64)|Uint(?:32|64)|Perm|Shuffle)\s*\(`),
		MatchType: detection.MatchFunctionCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("math/rand", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}
