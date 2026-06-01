# CBOM Scanner

A standalone CLI tool that scans source code for cryptographic assets, detects known vulnerabilities, and generates a **Cryptographic Bill of Materials (CBOM)** in [CycloneDX 1.6](https://cyclonedx.org/) format.

---

## What It Does

The scanner reads source files in a target directory, identifies every place cryptography is used — algorithms, keys, protocols, cipher suites — checks each one against a vulnerability database, and produces a structured report. The output tells you exactly what crypto is in your codebase, where it is, and which parts are a security risk.

---

## Features

### Detection
- **10 languages** — Go, Java, Python, JavaScript, TypeScript, C#, PHP, Ruby, Rust, Flutter/Dart
- **~470 detection rules** across all languages
- Covers standard libraries, popular third-party crypto libraries, and framework-level crypto APIs
- Concurrent file scanning using a goroutine worker pool
- `matchedText` on every CBOM asset — shows the exact source code text that triggered detection

### Vulnerability Analysis
- **51 vulnerability rules** covering weak algorithms, broken modes, insecure protocols, short key sizes, non-cryptographic PRNGs, deprecated keystores, and post-quantum readiness
- Severity levels: `critical`, `high`, `medium`, `low`, `info`
- ECB mode inference — `Cipher.getInstance("AES")` with no mode specified is automatically flagged as ECB

### VEX (Vulnerability Exploitability eXchange)
- **11 VEX rules** — additive exploitability assessment layer on top of vulnerability findings
- Status labels: `affected`, `not_affected`, `fixed`, `under_investigation`
- Does not modify or remove any existing CBOM fields

### Output
- **CycloneDX 1.6 JSON** CBOM with vulnerabilities and VEX embedded per component
- **SARIF 2.1.0** output for GitHub Advanced Security / Azure DevOps PR annotations
- **Terminal asset report table** — unique assets with Total Uses, Pass, Fail counts, colour-coded status
- **CI/CD exit code** — `--fail-on high` exits with code 1 when vulnerabilities at or above the threshold are found

### Enrichment
- OIDs, default key lengths, digest sizes, and block sizes added automatically from a built-in knowledge base

---

## Build

```bash
go build -o cbom-scanner ./cmd/cbom-scanner
```

---

## Usage

```bash
# Scan current directory
cbom-scanner

# Scan a specific project
cbom-scanner --dir /path/to/project

# Custom output file
cbom-scanner --dir /path/to/project --output my-cbom.json

# Also generate a SARIF report
cbom-scanner --dir /path/to/project --sarif results.sarif

# Fail CI pipeline if any high or critical vulnerability is found
cbom-scanner --dir /path/to/project --fail-on high

# Only show medium severity and above in output
cbom-scanner --dir /path/to/project --min-severity medium

# Control number of parallel scanning workers
cbom-scanner --dir /path/to/project --workers 8

# Verbose mode (shows file scan warnings)
cbom-scanner --dir /path/to/project --verbose
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | `.` | Directory to scan |
| `--output` | `cbom.json` | Output file path for the CBOM |
| `--sarif` | _(none)_ | Also write a SARIF 2.1.0 report to this path |
| `--format` | `json` | Output format (`json`) |
| `--fail-on` | _(none)_ | Exit code 1 if any vuln at or above this severity (`critical\|high\|medium\|low\|info`) |
| `--min-severity` | _(none)_ | Only include vulns at or above this severity in output |
| `--workers` | CPU count | Number of parallel file-scanning goroutines |
| `--verbose` | `false` | Show scan warnings and errors |
| `--version` | | Print version and exit |

---

## Output Format

### CBOM (CycloneDX 1.6 JSON)

Each component in the CBOM contains:

- **Asset type** — `algorithm`, `related-crypto-material`, or `protocol`
- **Crypto properties** — primitive type, mode, padding, OID, key length, block size, digest size, curve
- **Evidence** — exact file path, line number, and column of the detection
- **`matchedText`** — the exact source code expression that was matched
- **Vulnerabilities** — list of vulnerability rule IDs and severities, embedded directly in the component
- **VEX** — exploitability assessment for each vulnerability, embedded directly in the component

### Terminal Report

After each scan, a colour-coded table is printed:

```
  CBOM Asset Report
  ----------------------------------------------------------
  Asset                      Total Uses  Pass  Fail  Status
  ----------------------------------------------------------
  AES                        43          42    1     FAIL (HIGH)
  RSA                        12          12    0     PASS
  SHA1PRNG                   3           0     3     FAIL (HIGH)
  ...
  ----------------------------------------------------------
  Total Unique Assets: 35   Total Uses: 312   Pass: 292   Fail: 20
```

---

## Architecture

```
cmd/cbom-scanner/        CLI entry point and orchestrator
pkg/
├── model/               Data model (Algorithm, Key, Protocol, DetectionLocation)
├── detection/           Regex-based detection engine with worker pool
├── rules/
│   ├── golang/
│   │   └── stdlib.go        Go stdlib + tink, vault, caddy extras (66 rules)
│   ├── java/
│   │   ├── jca.go           Java Cryptography Architecture (21 rules)
│   │   ├── bouncycastle.go  BouncyCastle library (10 rules)
│   │   ├── spring.go        Spring Security (6 rules)
│   │   └── commons.go       Apache Commons Crypto (8 rules)
│   ├── python/
│   │   └── pyca.go          pyca, stdlib, PyCryptodome, PyNaCl, passlib,
│   │                        paramiko, PyJWT, liboqs (71 rules)
│   ├── javascript/
│   │   └── rules.go         Node.js crypto, Web Crypto, jose, jsonwebtoken,
│   │                        tweetnacl, crypto-js, bcrypt, argon2, node-forge (41 rules)
│   │                        [same rules registered for TypeScript]
│   ├── csharp/
│   │   └── rules.go         .NET crypto, BouncyCastle .NET, JWT, HKDF,
│   │                        BCrypt.Net, post-quantum (.NET 9+) (49 rules)
│   ├── php/
│   │   └── rules.go         openssl_*, sodium_*, phpseclib, firebase/php-jwt (61 rules)
│   ├── ruby/
│   │   └── rules.go         OpenSSL, Digest, BCrypt, JWT, Argon2 gems (30 rules)
│   ├── rust/
│   │   └── rules.go         ring, RustCrypto, rustls, JWT, password hashing (40 rules)
│   └── flutter/
│       └── cryptography.go  package:crypto, package:cryptography, PointyCastle,
│                            package:encrypt, dart:io TLS (32 rules)
├── enricher/            Adds OIDs, key lengths, digest sizes, block sizes
├── analyzer/            Matches detected assets against vulnerability rules
├── vulndb/              51 vulnerability rules (rule.go + rules.go)
├── vex/                 11 VEX rules (rule.go + rules.go + evaluator.go)
└── output/
    ├── cyclonedx.go     CycloneDX 1.6 CBOM generator
    ├── sarif.go         SARIF 2.1.0 report generator
    └── report.go        Terminal asset report table
```

---

## Detection Coverage by Language

### Go — 66 rules
`crypto/aes`, `crypto/cipher`, `crypto/des`, `crypto/rc4`, `crypto/hmac`, `crypto/sha256/512`, `crypto/md5`, `crypto/sha1`, `crypto/rsa`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/ed25519`, `crypto/tls`, `crypto/x509`, `crypto/rand`, `golang.org/x/crypto` (bcrypt, scrypt, Argon2, ChaCha20, Blake2, HKDF), Google Tink (AES-CMAC), Shamir secret sharing, TOTP/HOTP (`pquerna/otp`), post-quantum (`X25519MLKEM768`), `math/rand` (insecure PRNG flag)

### Java — 45 rules
**JCA (21):** `Cipher.getInstance`, `MessageDigest.getInstance`, `Signature.getInstance`, `Mac.getInstance`, `KeyGenerator.getInstance`, `KeyPairGenerator.getInstance`, `KeyFactory.getInstance`, `KeyAgreement.getInstance`, `SSLContext.getInstance`, `SecretKeyFactory.getInstance`, `SecureRandom`, `NullCipher`, `IvParameterSpec`, `KeyStore.getInstance`, `java.util.Random` (insecure)

**BouncyCastle (10):** Block/stream/AEAD cipher engines, digests, MACs, key generators, signers, key pair generators, key agreement, PBE generators

**Spring Security (6):** `MD5PasswordEncoder`, `ShaPasswordEncoder`, `BCryptPasswordEncoder`, `Argon2PasswordEncoder`, `Pbkdf2PasswordEncoder`, `SCryptPasswordEncoder`

**Apache Commons (8):** AES/DES/RSA/ECDSA encryption, PBKDF2, Argon2, scrypt, HMAC

### Python — 71 rules
**pyca/cryptography (31):** Symmetric ciphers, cipher modes, AEAD ciphers, hash algorithms, HMAC, CMAC, Poly1305, RSA/EC/DSA/DH key generation, Ed25519/Ed448/X25519/X448, KDFs, Fernet, RSA/EC signing, RSA encryption, cipher suites, SSL context, `os.urandom`, `secrets`, BLAKE3, ML-DSA, ML-KEM, ECDH exchange, bcrypt

**Python stdlib (4):** `hashlib`, `hmac`, PBKDF2, `os.urandom`

**PyCryptodome (7):** AES, symmetric ciphers, hashes, RSA/ECC, HMAC, KDFs

**PyNaCl (4):** Ed25519 signing, SecretBox, Box, VerifyKey

**PyJWT (2):** `jwt.encode`, `jwt.decode`

**passlib (2):** `hash.using()`, crypt import

**paramiko/SSH (4):** RSA key, ECDSA key, DSS key, transport auth

**Gap-fill rules (17):** TripleDES bare, DH classes, HMAC bare, hashlib bare, hash references, EC curve standalone, mode references, PKCS1v15, PKCS7, ECDSA sign, X25519 public key

**Insecure PRNG (1):** `random.random()`, `random.randint()`, `random.choice()` etc.

### JavaScript / TypeScript — 41 rules (registered for both languages)
**Node.js crypto:** `createCipher`, `createCipheriv`, `createDecipheriv`, `createHash`, `createHmac`, `generateKeyPair`, `sign`, `verify`, `randomBytes`, `pbkdf2`, `scrypt`, `hkdfSync`, `createDiffieHellman`

**Web Crypto API:** `subtle.encrypt/decrypt/digest/generateKey/importKey/sign/verify/deriveKey/deriveBits`

**Libraries:** jsonwebtoken, jose, tweetnacl, crypto-js, bcrypt, argon2, node-forge, TLS cipher strings

**Insecure PRNG:** `Math.random()`

### C# — 49 rules
**System.Security.Cryptography:** AES (Create/GCM/CCM/CNG/CSP), DES, TripleDES, RC2, Rijndael, cipher mode, SHA256/512/1/384/MD5/SHA3, HMAC, RSA, DSA, ECDsa, ECDiffieHellman, `Rfc2898DeriveBytes` (PBKDF2), HKDF (.NET 5+), `RandomNumberGenerator` (CSPRNG)

**TLS:** `SslStream`, `AuthenticateAsClient/Server`

**JWT:** `JwtSecurityToken`, `SecurityAlgorithms`, `JsonWebTokenHandler`

**BouncyCastle .NET:** Block cipher engines, digests, MACs, signers, key pair generators, PBE generators

**Post-quantum (.NET 9+):** ML-DSA, SLH-DSA, Composite-ML-DSA

**AEAD:** `AesCcm`, `ChaCha20Poly1305`

**ASP.NET Core:** `KeyDerivation.Pbkdf2`, `KeyDerivationPrf`, `EncryptionAlgorithm`, `ValidationAlgorithm`

**Third-party:** BCrypt.Net `HashPassword/VerifyPassword`, `X509Certificate2`

**Insecure PRNG:** `new System.Random()`

### PHP — 61 rules
**OpenSSL extension:** `openssl_encrypt/decrypt`, `openssl_sign/verify`, `openssl_pkey_new`, `openssl_digest`, `openssl_random_pseudo_bytes`, `openssl_public/private_encrypt/decrypt`, `openssl_seal/open`, `openssl_pkcs7_sign/verify`, `openssl_csr_new`

**Hash functions:** `hash()`, `hash_hmac()`, `hash_pbkdf2()`, `hash_init()`, `md5()`, `sha1()`

**Password hashing:** `password_hash()`, `password_verify()`, `crypt()`

**Built-in CSPRNG:** `random_bytes()`, `random_int()`

**Sodium extension:** AEAD, secretbox, box, sign, hash, pwhash, KDF, scalarmult, auth, shorthash

**mcrypt:** `mcrypt_encrypt()` (deprecated)

**Stream TLS:** `stream_context_create` SSL ciphers

**phpseclib:** AES, TripleDES, DES, Rijndael, Blowfish, Twofish, RC4, ChaCha20, Salsa20, RSA/EC/DSA/DH createKey, Hash, Random

**Third-party:** `firebase/php-jwt` encode/decode

**Insecure PRNG:** `rand()`, `mt_rand()`, `lcg_value()`

### Ruby — 30 rules
**OpenSSL:** `Cipher.new`, AES variants, `Digest.new`, `Digest` class methods, `HMAC.digest/hexdigest/base64digest`, `PKey::RSA/EC/DSA/DH.new`, `PKey.generate_key`, `.sign/.verify/.derive`, `SSL::SSLContext`, `SSL::SSLSocket`, SSL ciphers, SSL version, `PKCS5.pbkdf2_hmac`, `KDF.pbkdf2_hmac/scrypt/hkdf`, `Random.random_bytes`

**Digest stdlib:** `Digest::SHA256/MD5` class, `hexdigest`

**BCrypt gem:** `BCrypt::Password.create/new`, `BCrypt::Engine.hash_secret`

**jwt gem:** `JWT.encode`, `JWT.decode`

**SecureRandom stdlib:** `SecureRandom.hex/bytes/uuid`

**Argon2 gem:** `Argon2::Password.create/verify_password`

**Insecure PRNG:** `rand()`, `Random.rand()`, `Random.new()`

### Rust — 40 rules
**ring:** AEAD, digest, HMAC, signatures, PBKDF2, SystemRandom

**RustCrypto:** AES-GCM, ChaCha20Poly1305, AES-SIV, AES-CBC/CTR, SHA-2/3, MD5, BLAKE2/3, HMAC, RSA, Ed25519, X25519, ECDSA, Argon2, bcrypt, scrypt, PBKDF2, HKDF

**rustls:** TLS client/server config (with/without provider), cipher suites, signature schemes, SM4

**JWT:** `jsonwebtoken` encode/decode/Algorithm enum

**SQLCipher:** `PRAGMA key`

**Insecure PRNG:** `rand::thread_rng`, `rand::random`, `SmallRng`, `StdRng`, `ThreadRng`

### Flutter / Dart — 32 rules
**package:crypto:** Digest (md5/sha1/sha256/sha512), HMAC

**package:cryptography:** AES variants, ChaCha20, hash algorithms, HMAC, Ed25519, X25519, ECDH, ECDSA, RSA, KDFs (PBKDF2/scrypt/Argon2/HKDF), SecretBox

**package:pointycastle:** BlockCipher, PaddedBlockCipher, StreamCipher, Digest, MAC, KeyGenerator, Signer, AsymmetricKeyPairGenerator, KDF

**package:encrypt:** AES, RSA, Fernet

**dart:io TLS:** `SecureSocket.connect`, `SecurityContext`

**dart:math:** `Random.secure()` (CSPRNG), `Random()` (insecure PRNG flag)

**JWT:** `dart_jsonwebtoken` sign

**Database:** Isar AES-256 encryption key

---

## Vulnerability Rules (51 total)

| Category | Count | Examples |
|---|---|---|
| Hash | 5 | MD5, SHA-1, MD5 in signatures, SHA-1 MACs, RIPEMD-160 |
| Symmetric cipher | 5 | DES, RC4, ECB mode, 3DES, weak key size |
| Padding | 1 | PKCS#1 v1.5 |
| Protocol / TLS | 6 | SSLv2, SSLv3, TLS 1.0, TLS 1.1, NULL cipher, anonymous cipher |
| Key size | 5 | RSA < 2048, DSA < 2048, EC < 224, DH < 2048 |
| RNG | 2 | SHA1PRNG, non-cryptographic PRNG (all languages) |
| KDF | 3 | Weak PBE iteration count, PBKDF2 with weak hash, weak password hash scheme |
| CWE-1240 | 3 | NullCipher, hardcoded zero IV, weak PBE schemes |
| Keystore | 1 | Deprecated JKS format |
| National algo | 1 | GOST (RFC 7696) |
| Post-quantum | 7 | RSA, EC, DH, DSA, AES-128, AES-256, general PQC readiness |
| JWT | 2 | `none` algorithm, HS256 weak secret |
| Misc | 11 | Various protocol and cipher weaknesses |

---

## Extending

### Adding a new detection rule

Add a rule function in the appropriate file under `pkg/rules/`:

```go
func myNewRule() *detection.Rule {
    return &detection.Rule{
        ID:        "my-new-rule",
        Language:  detection.LangJava,
        Bundle:    "MyLibrary",
        Pattern:   regexp.MustCompile(`MyClass\.myMethod\(\s*"([^"]+)"`),
        MatchType: detection.MatchMethodCall,
        Extract: func(match []string, loc model.DetectionLocation) []model.INode {
            algo := model.NewAlgorithm(match[1], model.PrimitiveBlockCipher, loc)
            return []model.INode{algo}
        },
    }
}
```

Then add it to the relevant `allXxxRules()` slice in the same file.

### Adding a new vulnerability rule

Add a `VulnRule` in `pkg/vulndb/rules.go`:

```go
registry.Register(&VulnRule{
    ID:          "CBOM-MYCAT-001",
    Category:    "mycategory",
    Title:       "Short description",
    Description: "Detailed explanation of the vulnerability.",
    Severity:    "high",
    References:  []string{"CVE-XXXX-XXXX", "CWE-327"},
    Recommendation: "Use X instead of Y.",
    Match: func(node model.INode) bool {
        a, ok := node.(*model.Algorithm)
        return ok && strings.ToUpper(a.Name) == "MYALGO"
    },
})
```

### Adding a new language

1. Create `pkg/rules/yourlang/` with rule definitions
2. Add a `detection.Lang*` constant in `pkg/detection/rule.go`
3. Add the file extension mapping in `pkg/detection/engine.go`
4. Register rules in `cmd/cbom-scanner/main.go`

---

## Reference Files

| File | Purpose |
|------|---------|
| `CBOM_PLAN.md` | Full project reference — architecture, all rule files, model constants, CLI flags. Read this at the start of any dev session. |
| `DEVLOG.md` | Daily development journal — what was done, bugs fixed, thoughts, ideas. |
| `cbom_rules_reference.xlsx` | Spreadsheet of all detection rules by language and bundle. |
| `update_rules_reference.py` | Script to regenerate `cbom_rules_reference.xlsx` from the Go source. |
