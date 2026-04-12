package enricher

import (
	"strings"

	"github.com/cbom-scanner/pkg/model"
)

// Enrich post-processes detected nodes, adding OIDs, default key sizes, and other metadata.
func Enrich(nodes []model.INode) []model.INode {
	for _, node := range nodes {
		enrichNode(node)
	}
	return nodes
}

func enrichNode(node model.INode) {
	algo, ok := node.(*model.Algorithm)
	if !ok {
		// If this is a Key/Protocol, check children
		for _, child := range node.Children() {
			enrichNode(child)
		}
		return
	}

	name := strings.ToUpper(algo.Name)

	// Add OIDs
	if oid, ok := oidMap[name]; ok {
		if _, exists := algo.HasChildOfKind(model.KindOid); !exists {
			algo.Put(model.NewOid(oid))
		}
	}

	// Add default key length if none detected
	if _, exists := algo.HasChildOfKind(model.KindKeyLength); !exists {
		if keyLen, ok := defaultKeyLengths[name]; ok {
			algo.Put(model.NewKeyLength(keyLen))
		}
	}

	// Add digest size for hash algos
	if algo.PrimitiveType == model.PrimitiveHash || algo.PrimitiveType == model.PrimitiveXOF {
		if _, exists := algo.HasChildOfKind(model.KindDigestSize); !exists {
			if ds, ok := digestSizes[name]; ok {
				algo.Put(model.NewDigestSize(ds))
			}
		}
	}

	// Add block size for block ciphers
	if algo.PrimitiveType == model.PrimitiveBlockCipher || algo.PrimitiveType == model.PrimitiveAEAD {
		if _, exists := algo.HasChildOfKind(model.KindBlockSize); !exists {
			if bs, ok := blockSizes[name]; ok {
				algo.Put(model.NewBlockSize(bs))
			}
		}
	}

	// Add classical security level
	if _, exists := algo.HasChildOfKind(model.KindClassicalSecurityLevel); !exists {
		keyLen := 0
		if kl, ok := algo.HasChildOfKind(model.KindKeyLength); ok {
			if ip, ok2 := kl.(*model.IntProperty); ok2 {
				keyLen = ip.Value
			}
		}
		if level := computeClassicalSecurityLevel(name, algo.PrimitiveType, keyLen); level > 0 {
			algo.Put(model.NewClassicalSecurityLevel(level))
		}
	}

	// Enrich children recursively
	for _, child := range algo.Children() {
		enrichNode(child)
	}
}

// --- OID database (subset of most common algorithms) ---

var oidMap = map[string]string{
	// Symmetric ciphers
	"AES":    "2.16.840.1.101.3.4.1",
	"DES":    "1.3.14.3.2.7",
	"DESEDE": "1.2.840.113549.3.7",
	"3DES":   "1.2.840.113549.3.7",

	// Hash functions
	"MD5":      "1.2.840.113549.2.5",
	"SHA1":     "1.3.14.3.2.26",
	"SHA-1":    "1.3.14.3.2.26",
	"SHA224":   "2.16.840.1.101.3.4.2.4",
	"SHA-224":  "2.16.840.1.101.3.4.2.4",
	"SHA256":   "2.16.840.1.101.3.4.2.1",
	"SHA-256":  "2.16.840.1.101.3.4.2.1",
	"SHA384":   "2.16.840.1.101.3.4.2.2",
	"SHA-384":  "2.16.840.1.101.3.4.2.2",
	"SHA512":   "2.16.840.1.101.3.4.2.3",
	"SHA-512":  "2.16.840.1.101.3.4.2.3",
	"SHA3_224": "2.16.840.1.101.3.4.2.7",
	"SHA3_256": "2.16.840.1.101.3.4.2.8",
	"SHA3_384": "2.16.840.1.101.3.4.2.9",
	"SHA3_512": "2.16.840.1.101.3.4.2.10",

	// Asymmetric
	"RSA":     "1.2.840.113549.1.1.1",
	"DSA":     "1.2.840.10040.4.1",
	"EC":      "1.2.840.10045.2.1",
	"ECDSA":   "1.2.840.10045.4.3",
	"ED25519": "1.3.101.112",
	"ED448":   "1.3.101.113",
	"X25519":  "1.3.101.110",
	"X448":    "1.3.101.111",
	"DH":      "1.2.840.113549.1.3.1",

	// KDF
	"PBKDF2HMAC": "1.2.840.113549.1.5.12",
	"SCRYPT":     "1.3.6.1.4.1.11591.4.11",
	"HKDF":       "1.2.840.113549.1.9.16.3.28",
}

// --- Default key lengths in bits ---

var defaultKeyLengths = map[string]int{
	"AES":       256,
	"AES256":    256,
	"DES":       56,
	"DESEDE":    168,
	"3DES":      168,
	"TRIPLEDES": 168,
	"BLOWFISH":  128,
	"CAMELLIA":  256,
	"TWOFISH":   256,
	"SERPENT":   256,
	"ARIA":      256,
	"SM4":       128,
	"SEED":      128,
	"CAST5":     128,
	"IDEA":      128,
	"RC4":       128,
	"ARC4":      128,
	"CHACHA20":  256,
	"RSA":       2048,
	"DSA":       2048,
	"DH":        2048,
	"EC":        256,
	"ECDSA":     256,
	"ED25519":   256,
	"ED448":     448,
	"X25519":    256,
	"X448":      448,
}

// --- Digest output sizes in bits ---

var digestSizes = map[string]int{
	"MD5":      128,
	"SHA1":     160,
	"SHA-1":    160,
	"SHA224":   224,
	"SHA-224":  224,
	"SHA256":   256,
	"SHA-256":  256,
	"SHA384":   384,
	"SHA-384":  384,
	"SHA512":   512,
	"SHA-512":  512,
	"SHA3_224": 224,
	"SHA3_256": 256,
	"SHA3_384": 384,
	"SHA3_512": 512,
	"SM3":      256,
	"BLAKE2B":  512,
	"BLAKE2S":  256,
}

// --- Block sizes in bits ---

var blockSizes = map[string]int{
	"AES":       128,
	"AES256":    128,
	"DES":       64,
	"DESEDE":    64,
	"3DES":      64,
	"TRIPLEDES": 64,
	"BLOWFISH":  64,
	"CAMELLIA":  128,
	"TWOFISH":   128,
	"SERPENT":   128,
	"ARIA":      128,
	"SM4":       128,
	"SEED":      128,
	"CAST5":     64,
	"IDEA":      64,
}

// --- Classical Security Level computation ---
// Based on NIST SP 800-57 Part 1 Rev 5 (Table 2) and standard definitions.
// Security level is expressed in bits of classical (non-quantum) security.

func computeClassicalSecurityLevel(name string, prim model.Primitive, keyLen int) int {
	switch prim {
	case model.PrimitiveBlockCipher, model.PrimitiveStreamCipher, model.PrimitiveAEAD:
		return symmetricSecurityLevel(name, keyLen)
	case model.PrimitiveHash, model.PrimitiveXOF:
		return hashSecurityLevel(name)
	case model.PrimitiveMAC:
		return macSecurityLevel(name, keyLen)
	case model.PrimitiveSignature, model.PrimitivePublicKeyEncryption,
		model.PrimitiveKeyAgreement, model.PrimitiveKeyEncapsulation:
		return asymmetricSecurityLevel(name, keyLen)
	case model.PrimitiveKeyDerivation, model.PrimitivePasswordHash:
		return kdfSecurityLevel(name)
	}
	return 0
}

// symmetricSecurityLevel returns the security level for symmetric ciphers.
// For symmetric encryption, security level = key length (brute-force bound).
// Exception: 3DES has a meet-in-the-middle effective strength of ~112 bits.
func symmetricSecurityLevel(name string, keyLen int) int {
	switch name {
	case "DES":
		return 56
	case "3DES", "TDEA", "DESEDE", "TRIPLEDES":
		return 112 // effective due to meet-in-the-middle attack
	case "RC4", "ARC4":
		if keyLen > 0 {
			return keyLen
		}
		return 128
	case "CHACHA20":
		return 256
	case "AES", "AES256":
		if keyLen > 0 {
			return keyLen
		}
		return 256
	default:
		if keyLen > 0 {
			return keyLen
		}
	}
	return 0
}

// hashSecurityLevel returns the collision-resistance security level.
// For hash functions, classical security = output_size / 2 (birthday bound).
// MD5 and SHA-1 are marked at their theoretical value; both are practically broken.
func hashSecurityLevel(name string) int {
	switch name {
	case "MD2", "MD4", "MD5":
		return 64 // 128-bit output / 2; broken in practice
	case "SHA1", "SHA-1":
		return 80 // 160-bit output / 2; broken (SHAttered ~57 bits actual)
	case "SHA-224", "SHA224", "SHA3-224", "SHA3_224":
		return 112
	case "SHA-256", "SHA256", "SHA3-256", "SHA3_256", "SM3":
		return 128
	case "SHA-384", "SHA384", "SHA3-384", "SHA3_384":
		return 192
	case "SHA-512", "SHA512", "SHA3-512", "SHA3_512":
		return 256
	case "SHA-512/224", "SHA512_224":
		return 112
	case "SHA-512/256", "SHA512_256":
		return 128
	case "BLAKE2B":
		return 256
	case "BLAKE2S":
		return 128
	case "BLAKE3":
		return 128
	case "RIPEMD", "RIPEMD160":
		return 80 // 160-bit output / 2
	}
	return 0
}

// macSecurityLevel returns the security level for MAC algorithms.
// For HMAC, security = min(key_len, hash_output / 2).
func macSecurityLevel(name string, keyLen int) int {
	var hashBits int
	switch {
	case strings.Contains(name, "MD5"):
		hashBits = 64
	case strings.Contains(name, "SHA1") || strings.Contains(name, "SHA-1"):
		hashBits = 80
	case strings.Contains(name, "SHA256") || strings.Contains(name, "SHA-256"):
		hashBits = 128
	case strings.Contains(name, "SHA384") || strings.Contains(name, "SHA-384"):
		hashBits = 192
	case strings.Contains(name, "SHA512") || strings.Contains(name, "SHA-512"):
		hashBits = 256
	default:
		hashBits = 128
	}
	if keyLen > 0 && keyLen < hashBits {
		return keyLen
	}
	return hashBits
}

// asymmetricSecurityLevel returns the classical security level for asymmetric algorithms.
// Uses NIST SP 800-57 Part 1 Rev 5, Table 2.
func asymmetricSecurityLevel(name string, keyLen int) int {
	switch name {
	case "ED25519", "X25519":
		return 128
	case "ED448", "X448":
		return 224
	case "RSA", "DSA", "DH":
		return ffdhSecurityLevel(keyLen)
	case "EC", "ECDSA", "ECDH":
		return ecSecurityLevel(keyLen)
	case "P-224":
		return 112
	case "P-256":
		return 128
	case "P-384":
		return 192
	case "P-521":
		return 260
	}
	// For other asymmetric algorithms, fall back to FFDHE table
	if keyLen > 0 {
		return ffdhSecurityLevel(keyLen)
	}
	return 0
}

// ffdhSecurityLevel maps RSA/DSA/DH key sizes to classical security levels.
// Source: NIST SP 800-57 Part 1 Rev 5, Table 2.
func ffdhSecurityLevel(keyLen int) int {
	switch {
	case keyLen < 1024:
		return 56
	case keyLen < 2048:
		return 80
	case keyLen < 3072:
		return 112
	case keyLen < 4096:
		return 128
	case keyLen < 7680:
		return 140
	case keyLen < 15360:
		return 192
	default:
		return 256
	}
}

// ecSecurityLevel maps ECC key sizes to classical security levels.
// For ECC, the classical security level is approximately keyLen / 2.
func ecSecurityLevel(keyLen int) int {
	switch {
	case keyLen <= 0:
		return 0
	case keyLen <= 224:
		return 112
	case keyLen <= 256:
		return 128
	case keyLen <= 384:
		return 192
	default:
		return keyLen / 2
	}
}

// kdfSecurityLevel returns a nominal security level for KDFs and password hashers.
func kdfSecurityLevel(name string) int {
	switch name {
	case "PBKDF2", "PBKDF2HMAC":
		return 128 // depends on hash; assume SHA-256 default
	case "BCRYPT":
		return 128
	case "SCRYPT":
		return 128
	case "ARGON2", "ARGON2ID", "ARGON2I", "ARGON2D":
		return 128
	case "HKDF":
		return 128
	}
	return 0
}
