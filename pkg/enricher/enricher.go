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
