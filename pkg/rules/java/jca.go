package java

import (
	"regexp"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// knownBogusJCAAlgos lists placeholder/test strings and non-cryptographic
// algorithm names that may appear inside Cipher/MessageDigest/Mac/Signature
// .getInstance() calls in test or example code. We skip these to avoid
// false positives.
var knownBogusJCAAlgos = map[string]bool{
	// Test / placeholder strings
	"FOO": true, "BAR": true, "BAZ": true, "ABCDEF": true, "TEST": true, "DUMMY": true,
	// xxHash — non-cryptographic
	"XXH3": true, "XXH128": true, "XXH32": true, "XXH64": true,
}

// RegisterJCADetectionRules registers all Java Cryptography Architecture detection rules.
func RegisterJCADetectionRules(registry *detection.RuleRegistry) {
	for _, r := range jcaRules() {
		registry.Register(r)
	}
}

func jcaRules() []*detection.Rule {
	return []*detection.Rule{
		cipherGetInstance(),
		messageDigestGetInstance(),
		signatureGetInstance(),
		macGetInstance(),
		keyGeneratorGetInstance(),
		keyPairGeneratorGetInstance(),
		secretKeySpecConstructor(),
		keyFactoryGetInstance(),
		keyAgreementGetInstance(),
		sslContextGetInstance(),
		secretKeyFactoryGetInstance(),
		secureRandomGetInstance(),
		secureRandomConstructor(),
		secureRandomGetInstanceStrong(),
		nullCipherConstructor(),
		ivParameterSpecWithNewByteArray(),
		keyStoreGetInstance(),
		keyStoreGetKey(),
		keyStoreSetKeyEntry(),
		jcaContentSignerBuilder(),
		javaInsecureRandom(),
	}
}

// --- Cipher.getInstance ---

func cipherGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-cipher-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`Cipher\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract:   extractCipherAlgorithm,
	}
}

func extractCipherAlgorithm(match []string, loc model.DetectionLocation) []model.INode {
	if len(match) < 2 {
		return nil
	}
	raw := match[1] // e.g. "AES/CBC/PKCS5Padding"
	if knownBogusJCAAlgos[strings.ToUpper(strings.Split(raw, "/")[0])] {
		return nil
	}
	parts := strings.Split(raw, "/")

	algoName := parts[0]
	prim := classifyCipherPrimitive(algoName)
	algo := model.NewAlgorithm(algoName, prim, loc)
	algo.AddFunction(model.FuncEncrypt)
	algo.AddFunction(model.FuncDecrypt)

	if len(parts) > 1 && parts[1] != "" {
		algo.Put(model.NewMode(parts[1]))
	} else if prim == model.PrimitiveBlockCipher {
		// No mode specified — Java silently defaults to ECB, which is insecure.
		// Inject ECB explicitly so CBOM-ECB-001 fires on this asset.
		algo.Put(model.NewMode("ECB"))
		loc.MatchedText = loc.MatchedText + " [ECB inferred: no mode specified defaults to ECB in Java]"
	}
	if len(parts) > 2 && parts[2] != "" {
		algo.Put(model.NewPadding(parts[2]))
	}

	return []model.INode{algo}
}

// --- MessageDigest.getInstance ---

func messageDigestGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-messagedigest-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`MessageDigest\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			if knownBogusJCAAlgos[strings.ToUpper(match[1])] {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

// --- Signature.getInstance ---

func signatureGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-signature-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`Signature\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			if knownBogusJCAAlgos[strings.ToUpper(match[1])] {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncSign)
			algo.AddFunction(model.FuncVerify)
			return []model.INode{algo}
		},
	}
}

// --- Mac.getInstance ---

func macGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-mac-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`Mac\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			if knownBogusJCAAlgos[strings.ToUpper(match[1])] {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveMAC, loc)
			algo.AddFunction(model.FuncTag)
			return []model.INode{algo}
		},
	}
}

// --- KeyGenerator.getInstance ---

func keyGeneratorGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-keygenerator-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`KeyGenerator\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], classifyCipherPrimitive(match[1]), loc)
			algo.AddFunction(model.FuncKeyGen)
			key := model.NewKey(match[1], model.KindSecretKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- KeyPairGenerator.getInstance ---

func keyPairGeneratorGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-keypairgenerator-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`KeyPairGenerator\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := classifyAsymmetricPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncKeyGen)
			pubKey := model.NewKey(match[1], model.KindPublicKey, loc)
			pubKey.Put(algo)
			privKey := model.NewKey(match[1], model.KindPrivateKey, loc)
			privKey.Put(algo)
			return []model.INode{pubKey, privKey}
		},
	}
}

// --- SecretKeySpec constructor ---

func secretKeySpecConstructor() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-secretkeyspec",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`new\s+SecretKeySpec\s*\([^,]+,\s*"([^"]+)"\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			// "RAW" is a key encoding format, not a crypto algorithm — skip it.
			if strings.EqualFold(match[1], "RAW") {
				return nil
			}
			algo := model.NewAlgorithm(match[1], classifyCipherPrimitive(match[1]), loc)
			key := model.NewKey(match[1], model.KindSecretKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- KeyFactory.getInstance ---

func keyFactoryGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-keyfactory-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`KeyFactory\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := classifyAsymmetricPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			key := model.NewKey(match[1], model.KindKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- KeyAgreement.getInstance ---

func keyAgreementGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-keyagreement-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`KeyAgreement\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// --- SSLContext.getInstance ---

func sslContextGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-sslcontext-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`SSLContext\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			proto := model.NewProtocol(match[1], loc)
			return []model.INode{proto}
		},
	}
}

// --- SecretKeyFactory.getInstance ---

func secretKeyFactoryGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-secretkeyfactory-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`SecretKeyFactory\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			prim := classifyKDFPrimitive(match[1])
			algo := model.NewAlgorithm(match[1], prim, loc)
			algo.AddFunction(model.FuncKeyDerive)
			key := model.NewKey(match[1], model.KindSecretKey, loc)
			key.Put(algo)
			return []model.INode{key}
		},
	}
}

// --- Classification helpers ---

// --- NullCipher constructor (CWE-1240) ---
// NullCipher is a Java cipher that performs no encryption at all.
// Any use of it in production code disables confidentiality entirely.

func nullCipherConstructor() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-nullcipher-new",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`new\s+NullCipher\s*\(\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("NullCipher", model.PrimitiveBlockCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- IvParameterSpec with new byte array (CWE-1240) ---
// Detects IvParameterSpec constructed with a newly allocated byte array literal,
// which defaults to all-zero bytes — a hardcoded/static IV that breaks semantic security.

func ivParameterSpecWithNewByteArray() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-ivparameterspec-zero",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("HardcodedIV", model.PrimitiveUnknown, loc)
			return []model.INode{algo}
		},
	}
}

// --- SecureRandom.getInstance("SHA1PRNG") ---

func secureRandomGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-securerandom-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`SecureRandom\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// --- new SecureRandom() ---
// Detects default-constructor usage — the JVM picks the algorithm automatically.

func secureRandomConstructor() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-securerandom-new",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`new\s+SecureRandom\s*\(\s*\)`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SecureRandom", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// --- SecureRandom.getInstanceStrong() ---
// Guaranteed to return a strong CSPRNG backed by the OS entropy source.
// This is the recommended Java API for security-sensitive key generation.

func secureRandomGetInstanceStrong() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-securerandom-getInstanceStrong",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`SecureRandom\s*\.\s*getInstanceStrong\s*\(\s*\)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SecureRandom.getInstanceStrong", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// --- KeyStore.getInstance("JKS") / KeyStore.getInstance("PKCS12") ---
// Captures the keystore type. JKS is a proprietary Sun format deprecated since
// Java 9 in favour of PKCS12. It uses 3DES encryption and SHA-1 MACs, making
// it weaker than the PKCS12 standard.

func keyStoreGetInstance() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-keystore-getInstance",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`KeyStore\s*\.\s*getInstance\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm("KeyStore-"+match[1], model.PrimitiveUnknown, loc)
			return []model.INode{algo}
		},
	}
}

// --- keyStore.getKey("alias", ...) ---
// Captures the key alias used to retrieve a private/secret key from a KeyStore.
// The alias becomes the component name, providing key-id information in the CBOM.

func keyStoreGetKey() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-keystore-getKey",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`\.getKey\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			key := model.NewKey(match[1], model.KindPrivateKey, loc)
			return []model.INode{key}
		},
	}
}

// --- keyStore.setKeyEntry("alias", ...) ---
// Captures the alias assigned when storing a private key in a KeyStore.
// Provides key-id information and tracks which private keys are persisted.

func keyStoreSetKeyEntry() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-keystore-setKeyEntry",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`\.setKeyEntry\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			key := model.NewKey(match[1], model.KindPrivateKey, loc)
			return []model.INode{key}
		},
	}
}

// --- JcaContentSignerBuilder (BouncyCastle certificate signing) ---
// Detects X.509 certificate signing via BouncyCastle's JcaContentSignerBuilder.
// The algorithm string (e.g. "SHA1withRSA", "MD5withRSA") specifies the hash+key
// algorithm used to sign the certificate. Weak algorithms here directly produce
// vulnerable certificates (CBOM-CERT-001, CBOM-CERT-002).

func jcaContentSignerBuilder() *detection.Rule {
	return &detection.Rule{
		ID:        "jca-contentSignerBuilder",
		Language:  detection.LangJava,
		Bundle:    "JCA",
		Pattern:   regexp.MustCompile(`new\s+JcaContentSignerBuilder\s*\(\s*"([^"]+)"`),
		MatchType: detection.MatchConstructor,
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

// --- java.util.Random / ThreadLocalRandom — insecure PRNG ---
// new Random() and ThreadLocalRandom produce non-cryptographic pseudo-random
// output that is predictable given the seed. They must not be used for
// security-sensitive values such as tokens, nonces, or passwords.

func javaInsecureRandom() *detection.Rule {
	return &detection.Rule{
		ID:       "jca-insecure-random",
		Language: detection.LangJava,
		Bundle:   "JCA",
		Pattern:  regexp.MustCompile(`\bnew\s+(?:java\.util\.)?Random\s*\(|\bThreadLocalRandom\s*\.\s*current\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("java.util.Random", model.PrimitivePRNG, loc)
			algo.AddFunction(model.FuncGenerate)
			return []model.INode{algo}
		},
	}
}

// --- Classification helpers ---

func classifyCipherPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "AES") && strings.Contains(upper, "GCM"):
		return model.PrimitiveAEAD
	case strings.Contains(upper, "CHACHA20") && strings.Contains(upper, "POLY"):
		return model.PrimitiveAEAD
	case strings.Contains(upper, "AES"), strings.Contains(upper, "DES"),
		strings.Contains(upper, "BLOWFISH"), strings.Contains(upper, "CAMELLIA"),
		strings.Contains(upper, "TWOFISH"), strings.Contains(upper, "SERPENT"),
		strings.Contains(upper, "ARIA"), strings.Contains(upper, "SM4"),
		strings.Contains(upper, "SEED"), strings.Contains(upper, "CAST"):
		return model.PrimitiveBlockCipher
	case strings.Contains(upper, "RC4"), strings.Contains(upper, "CHACHA"),
		strings.Contains(upper, "SALSA"), strings.Contains(upper, "GRAIN"):
		return model.PrimitiveStreamCipher
	default:
		return model.PrimitiveUnknown
	}
}

func classifyAsymmetricPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "RSA"):
		return model.PrimitivePublicKeyEncryption
	case strings.Contains(upper, "EC"), strings.Contains(upper, "ECDSA"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "DSA"):
		return model.PrimitiveSignature
	case strings.Contains(upper, "DH"), strings.Contains(upper, "ECDH"),
		strings.Contains(upper, "DIFFIEHELLMAN"):
		return model.PrimitiveKeyAgreement
	default:
		return model.PrimitiveUnknown
	}
}

func classifyKDFPrimitive(name string) model.Primitive {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "PBKDF"), strings.Contains(upper, "PBE"):
		return model.PrimitivePasswordHash
	case strings.Contains(upper, "HKDF"), strings.Contains(upper, "SCRYPT"),
		strings.Contains(upper, "ARGON"):
		return model.PrimitiveKeyDerivation
	default:
		return model.PrimitiveUnknown
	}
}
