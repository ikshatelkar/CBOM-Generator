package java

import (
	"regexp"
	"strings"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterBouncyCastleDetectionRules registers BouncyCastle lightweight API detection rules.
func RegisterBouncyCastleDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range bcRules() {
		registry.Register(r)
	}
}

func bcRules() []*detection.Rule {
	return []*detection.Rule{
		bcBlockCipherEngine(),
		bcStreamCipherEngine(),
		bcAEADCipher(),
		bcDigest(),
		bcMac(),
		bcKeyGenerator(),
		bcSigner(),
		bcKeyPairGenerator(),
		bcKeyAgreement(),
		bcPBEParametersGenerator(),
	}
}

// --- Block cipher engines: new AESEngine(), new DESEngine(), etc. ---

func bcBlockCipherEngine() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-block-cipher-engine",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(AES|DES|DESede|Blowfish|Twofish|Serpent|Camellia|ARIA|SM4|CAST5|CAST6|IDEA|Noekeon|RC2|RC5|RC6|SEED|Skipjack|TEA|XTEA|Shacal2)(?:Engine|FastEngine|LightEngine)\s*\(`),
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

// --- Stream cipher engines: new ChaCha7539Engine(), new RC4Engine(), etc. ---

func bcStreamCipherEngine() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-stream-cipher-engine",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(ChaCha\d*|Salsa20|XSalsa20|HC128|HC256|RC4|Grain\w*|VMPC|Zuc\w*)Engine\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveStreamCipher, loc)
			algo.AddFunction(model.FuncEncrypt)
			algo.AddFunction(model.FuncDecrypt)
			return []model.INode{algo}
		},
	}
}

// --- AEAD ciphers: new GCMBlockCipher(), new CCMBlockCipher(), etc. ---

func bcAEADCipher() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-aead-cipher",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(GCM|CCM|EAX|OCB|SIV|ChaCha20Poly1305)(?:BlockCipher|Engine)?\s*\(`),
		MatchType: detection.MatchConstructor,
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

// --- Digests: new SHA256Digest(), new SHA3Digest(), etc. ---

func bcDigest() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-digest",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(SHA\d+|SHA3|MD5|MD4|MD2|RIPEMD\d+|Whirlpool|Tiger|GOST3411|Blake2b|Blake2s|Blake3|SM3|Keccak|SHAKE|Skein)\w*Digest\s*\(`),
		MatchType: detection.MatchConstructor,
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

// --- MACs: new HMac(), new CMac(), etc. ---

func bcMac() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-mac",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(HMac|CMac|GMac|CBCBlockCipherMac|CFBBlockCipherMac|Poly1305|SipHash|KMAC)\s*\(`),
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

// --- Key generators: explicit list of known BC symmetric algorithm key generators ---

func bcKeyGenerator() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-keygen",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(AES|DES|DESede|Blowfish|Twofish|Camellia|ARIA|SM4|SEED|CAST5|CAST6|IDEA|RC2|RC4|RC5|RC6|ChaCha20|Salsa20|Noekeon|Skipjack|TEA|XTEA)KeyGenerator\s*\(`),
		MatchType: detection.MatchConstructor,
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

// --- Signers: new RSADigestSigner(), new ECDSASigner(), etc. ---

func bcSigner() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-signer",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(RSA\w*|ECDSA|Ed25519|Ed448|DSA|SM2|GOST3410|Rainbow|Dilithium|Falcon|Sphincs|XMSS|LMS|Picnic)\w*Signer\s*\(`),
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

// --- Key pair generators ---

func bcKeyPairGenerator() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-keypairgen",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(RSA|EC|DSA|DH|Ed25519|Ed448|SM2|GOST3410|Dilithium|Falcon|Sphincs|XMSS|Kyber|NTRU|SABER|FrodoKEM|BIKE|HQC|CMCE)\w*KeyPairGenerator\s*\(`),
		MatchType: detection.MatchConstructor,
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

// --- Key agreement ---

func bcKeyAgreement() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-keyagreement",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(ECDH|DH|X25519|X448|SM2)\w*Agreement\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitiveKeyAgreement, loc)
			return []model.INode{algo}
		},
	}
}

// --- PBE parameter generators ---

func bcPBEParametersGenerator() *detection.Rule {
	return &detection.Rule{
		ID:       "bc-pbe-paramgen",
		Language: detection.LangJava,
		Bundle:   "BouncyCastle",
		Pattern: regexp.MustCompile(
			`new\s+(PKCS5S2|PKCS12|OpenSSL|Scrypt|Argon2)\w*ParametersGenerator\s*\(`),
		MatchType: detection.MatchConstructor,
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
