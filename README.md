# cbom-scanner

A standalone CLI tool that detects cryptographic assets in source code and generates a **Cryptographic Bill of Materials (CBOM)** in [CycloneDX 1.6](https://cyclonedx.org/) format.

## Features

- **Java** detection: JCA (`Cipher`, `MessageDigest`, `Signature`, `Mac`, `KeyGenerator`, etc.) and BouncyCastle lightweight API
- **Python** detection: pyca/cryptography (`algorithms`, `hashes`, `hmac`, KDFs, AEAD, signing, key generation, etc.)
- Enrichment layer adds OIDs, default key sizes, digest sizes, and block sizes
- CycloneDX 1.6 compliant JSON output
- Zero external dependencies — pure Go stdlib

## Build

```bash
go build -o cbom-scanner ./cmd/cbom-scanner
```

## Usage

```bash
# Scan current directory
cbom-scanner

# Scan a specific project
cbom-scanner -dir /path/to/project

# Custom output file
cbom-scanner -dir /path/to/project -output my-cbom.json

# Verbose mode (shows warnings)
cbom-scanner -dir /path/to/project -verbose
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-dir` | `.` | Directory to scan |
| `-output` | `cbom.json` | Output file path |
| `-format` | `json` | Output format (json) |
| `-verbose` | `false` | Show warnings and errors |
| `-version` | | Print version and exit |

## Output

The tool generates a CycloneDX 1.6 CBOM JSON file containing:

- **Algorithm components**: detected crypto algorithms with primitive type, mode, padding, OID, key length, block size, digest size
- **Key components**: detected key material (secret, public, private keys)
- **Protocol components**: detected protocols (TLS, SSL, etc.)
- **Cipher suite components**: detected cipher suite names
- **Dependencies**: relationships between components (e.g., key → algorithm)
- **Evidence**: file path, line, and column of each detection

## Architecture

```
cmd/cbom-scanner/        CLI entry point
pkg/
├── model/               Data model (Algorithm, Key, Protocol, properties)
├── detection/           Pattern-matching detection engine
├── rules/
│   ├── java/            JCA + BouncyCastle detection rules
│   └── python/          pyca/cryptography detection rules
├── enricher/            Post-processing (OIDs, defaults)
└── output/              CycloneDX CBOM generator
```

### Detection Rules (42 total)

**Java JCA (12 rules):** Cipher, MessageDigest, Signature, Mac, KeyGenerator, KeyPairGenerator, SecretKeySpec, KeyFactory, KeyAgreement, AlgorithmParameterGenerator, SSLContext, SecretKeyFactory

**Java BouncyCastle (10 rules):** Block cipher engines, stream ciphers, AEAD ciphers, digests, MACs, key generators, signers, key pair generators, key agreement, PBE parameter generators

**Python pyca/cryptography (20 rules):** Symmetric algorithms, cipher modes, AEAD ciphers, hash algorithms, HMAC, RSA/EC/DSA/DH key generation, Ed25519/Ed448, X25519/X448, KDFs, Fernet, RSA/EC signing, RSA encryption, cipher suites, SSL context

## Extending

### Adding a new detection rule

Add a rule function in the appropriate package under `pkg/rules/`:

```go
func myNewRule() *detection.Rule {
    return &detection.Rule{
        ID:       "my-new-rule",
        Language: detection.LangJava,
        Bundle:   "MyLibrary",
        Pattern:  regexp.MustCompile(`MyClass\.myMethod\(\s*"([^"]+)"`),
        MatchType: detection.MatchMethodCall,
        Extract: func(match []string, loc model.DetectionLocation) []model.INode {
            algo := model.NewAlgorithm(match[1], model.PrimitiveBlockCipher, loc)
            return []model.INode{algo}
        },
    }
}
```

Then register it in the `Register*` function.

### Adding a new language

1. Create `pkg/rules/yourlang/` with rule definitions
2. Add `detection.Lang*` constant in `pkg/detection/rule.go`
3. Add language extension mapping in `pkg/detection/engine.go`
4. Register rules in `cmd/cbom-scanner/main.go`
