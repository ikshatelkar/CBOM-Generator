# CBOM Scanner — Project Context Reference

> **Purpose of this file:** Read this file at the start of any chat session to get full context
> of the project without exploring the codebase. It covers everything: architecture, all source
> files, detection rules (423 total), vulnerability rules (49), VEX rules (10), CLI flags,
> output format, and how to extend the scanner.

---

## 1. What is CBOM Scanner?

A **Cryptographic Bill of Materials (CBOM) scanner** written in Go (v0.1.0).

It scans source code directories for cryptographic asset usage — algorithms, keys, protocols,
cipher suites — using regex-based detection rules, then:

1. **Detects** crypto assets across 10 programming languages
2. **Enriches** them with OIDs, default key sizes, block sizes, digest sizes
3. **Analyses** them against a vulnerability database (CBOM-HASH-001 … CBOM-JWT-002)
4. **Evaluates** exploitability via a VEX (Vulnerability Exploitability eXchange) layer
5. **Outputs** a CycloneDX 1.6 JSON CBOM + optional SARIF 2.1.0 report

---

## 2. Project Root

```
c:\Users\Nochu\OneDrive\cbomscanner\cbom-scanner\
```

---

## 3. Complete File Tree

```
cbom-scanner/
├── cmd/
│   └── cbom-scanner/
│       └── main.go                  ← CLI entry point, flag parsing, pipeline orchestration
├── pkg/
│   ├── detection/
│   │   ├── rule.go                  ← Rule struct, RuleRegistry, Language constants
│   │   ├── engine.go                ← ScanDirectory (concurrent), ScanFile (line-by-line regex)
│   │   └── engine_test.go
│   ├── model/
│   │   ├── node.go                  ← NodeKind, Primitive, CryptoFunc constants; INode interface
│   │   ├── algorithm.go             ← Algorithm struct + NewAlgorithm()
│   │   ├── key.go                   ← Key struct + NewKey()
│   │   └── properties.go            ← KeyLength, BlockSize, DigestSize, Mode, Curve, etc.
│   ├── enricher/
│   │   └── enricher.go              ← Adds OIDs, default key lengths, digest/block sizes
│   ├── analyzer/
│   │   └── analyzer.go              ← Runs VulnDB rules against detected nodes
│   ├── vulndb/
│   │   ├── rule.go                  ← VulnRule struct + VulnRuleRegistry
│   │   └── rules.go                 ← 49 vulnerability rules (CBOM-HASH-001 … CBOM-JWT-002)
│   ├── vex/
│   │   ├── rule.go                  ← VEXRule struct
│   │   ├── evaluator.go             ← VEX evaluation logic
│   │   └── rules.go                 ← 10 VEX rules
│   ├── output/
│   │   ├── cyclonedx.go             ← CycloneDX 1.6 BOM builder + WriteJSON()
│   │   ├── report.go                ← PrintReport() table to stdout
│   │   └── sarif.go                 ← SARIF 2.1.0 report writer
│   └── rules/                       ← All detection rules (423 total)
│       ├── golang/      stdlib.go   ← 66 Go rules
│       ├── java/        jca.go      ← 20 Java JCA rules
│       │                commons.go  ←  8 Java common library rules (JJWT, Apache Commons)
│       │                spring.go   ←  6 Spring Security rules
│       │                bouncycastle.go ← 10 BouncyCastle rules
│       ├── python/      pyca.go     ← 70 Python pyca/cryptography rules
│       ├── php/         rules.go    ← 60 PHP rules
│       ├── ruby/        rules.go    ← 28 Ruby rules
│       ├── flutter/     cryptography.go ← 31 Dart/Flutter rules
│       ├── csharp/      rules.go    ← 46 C# rules
│       ├── javascript/  rules.go    ← 39 JS/TS rules
│       └── rust/        rules.go    ← 39 Rust rules
├── cbom-scanner.exe                 ← Compiled Windows binary
├── cbom.json                        ← Sample CBOM output (from last scan)
├── cbom_hiddify.json                ← CBOM output from hiddify scan
├── cbom_rules_reference.xlsx        ← Excel reference of all 423 rules (auto-generated)
├── update_rules_reference.py        ← Python script that regenerates the Excel
├── generate_cbom_report.py          ← Python script that generates a scan security report Excel
└── PROJECT_CONTEXT.md               ← THIS FILE
```

---

## 4. CLI Usage

```bash
# Basic scan
./cbom-scanner.exe --dir /path/to/repo --output cbom.json

# All flags
./cbom-scanner.exe \
  --dir         <directory>      # directory to scan (default: .)
  --output      <file.json>      # CBOM output path (default: cbom.json)
  --sarif       <file.sarif>     # also write SARIF 2.1.0 report
  --format      json             # output format (currently only json)
  --fail-on     <severity>       # exit code 1 if severity >= threshold
  --min-severity <severity>      # filter output to >= severity only
  --workers     <n>              # parallel goroutines (default: CPU count)
  --verbose                      # print scan warnings
  --version                      # print version and exit
```

Severity levels (low → high): `info` → `low` → `medium` → `high` → `critical`

---

## 5. Pipeline (Step by Step)

```
Source Files
    │
    ▼
[1] Rule Registry    ← All 423 detection rules loaded from pkg/rules/*
    │
    ▼
[2] Detection Engine ← Scans files line-by-line with regex; concurrent worker pool
    │                   Skips: .git, node_modules, __pycache__, vendor, target, build, .idea
    │                   Detects: .java .py .go .dart .js .jsx .mjs .cjs .ts .tsx .cs .php .rb .rs
    ▼
[3] Enricher         ← Adds OIDs, default key lengths, block/digest sizes to detected nodes
    │
    ▼
[4] VulnDB Analyzer  ← 49 rules fire on enriched nodes → produces vulnerability findings
    │
    ▼
[5] Severity Filter  ← (optional --min-severity) drops below-threshold findings
    │
    ▼
[6] VEX Evaluator    ← 10 rules produce VEX exploitability assessments per component
    │
    ▼
[7] CycloneDX Output ← Builds BOM JSON (CycloneDX 1.6), writes cbom.json
    │
    ▼
[8] SARIF Output     ← (optional --sarif) writes SARIF 2.1.0 report
    │
    ▼
[9] Console Report   ← Table + Summary + VEX breakdown printed to stdout
```

---

## 6. Core Data Model (`pkg/model/`)

### Node types (INode interface)
| Type | Kind constant | Description |
|------|--------------|-------------|
| `*Algorithm` | `KindAlgorithm` | Detected crypto algorithm (AES, SHA-256, RSA…) |
| `*Key` | `KindKey/KindPublicKey/KindPrivateKey/KindSecretKey` | Cryptographic key |
| `*Protocol` | `KindProtocol` | TLS, SSH, etc. |
| `*CipherSuite` | `KindCipherSuite` | TLS cipher suite |

### Primitive types (Algorithm.PrimitiveType)
`block-cipher` · `stream-cipher` · `ae` (AEAD) · `hash` · `mac` · `signature` ·
`pke` (public-key encryption) · `key-agree` · `kem` · `kdf` · `pbkdf` ·
`drbg` (PRNG) · `xof` · `mgf` · `unknown`

### CryptoFunc (operations detected)
`encrypt` · `decrypt` · `sign` · `verify` · `generate` · `keyderive` · `keygen` ·
`digest` · `tag` · `encapsulate` · `decapsulate` · `keywrap` · `keyunwrap`

### Rule struct (pkg/detection/rule.go)
```go
type Rule struct {
    ID        string         // unique identifier e.g. "go-aes-newcipher"
    Language  Language       // e.g. detection.LangGo
    Bundle    string         // library group e.g. "GoStdlib", "JCA", "Pyca"
    Pattern   *regexp.Regexp // regex matched against each source line
    MatchType MatchType      // MatchFunctionCall | MatchMethodCall | MatchConstructor | MatchImport
    Extract   ExtractFunc    // func(match []string, loc DetectionLocation) []model.INode
    DependsOn []string       // parent rule IDs (chained detection)
}
```

---

## 7. Detection Rules Summary (423 total)

### Go — 66 rules (`pkg/rules/golang/stdlib.go`)
**Bundles:** GoStdlib, GoXCrypto, GoJWT, GoVault, GoOTP, GoTink

| Category | Rules |
|----------|-------|
| Symmetric ciphers | AES, DES, 3DES, RC4 |
| Cipher modes | GCM, CBC, CFB, OFB, CTR |
| Hash | MD5, SHA-1, SHA-256/224, SHA-512/384/224/256, SHA-3 |
| HMAC | hmac.New with hash capture |
| RSA | GenerateKey, EncryptPKCS1v15/OAEP, DecryptPKCS1v15/OAEP, SignPKCS1v15/PSS, VerifyPKCS1v15/PSS |
| ECDSA | GenerateKey (with curve), Sign, Verify, elliptic.P224/256/384/521 |
| ECDH | crypto/ecdh — P256/P384/P521/X25519 GenerateKey |
| Ed25519 | GenerateKey, Sign, Verify |
| DSA | GenerateKey |
| CSPRNG | crypto/rand Read/Int/Prime/Text |
| TLS | MinVersion, Dial/Client, Listen/Server, CipherSuites (uint16), CurvePreferences, LoadX509KeyPair |
| Post-Quantum | tls.X25519MLKEM768 (Go 1.23+ hybrid KEM) |
| x509 | CreateCertificate(Request), ParseCertificate(s/Request), ParsePKCS8/PKCS1/EC PrivateKey, Marshal* |
| x/crypto | ChaCha20-Poly1305, XChaCha20-Poly1305, Argon2id, Argon2i, bcrypt, PBKDF2, scrypt, BLAKE2b/s, NaCl box/secretbox, HKDF, X25519/Curve25519, ChaCha20 (unauthenticated) |
| JWT | jwt.NewWithClaims, jwt.SigningMethod* (HS/RS/PS/ES/EdDSA/none) |
| Shamir | shamir.Split / shamir.Combine |
| OTP | totp.Generate/Validate, hotp.Generate/Validate |
| Tink | subtle.NewAESCMAC (AES-CMAC) |
| Insecure PRNG | math/rand usage |

### Java — 44 rules (`pkg/rules/java/`)
**Bundles:** JCA, BouncyCastle, Spring, Commons

| File | Key detections |
|------|---------------|
| jca.go | Cipher.getInstance, MessageDigest.getInstance, KeyPairGenerator.getInstance, Signature.getInstance, KeyFactory.getInstance, SecretKeySpec, IvParameterSpec, SecureRandom, KeyStore, NullCipher, java.util.Random |
| bouncycastle.go | BC-specific cipher/digest/MAC/key classes |
| spring.go | Spring Security password encoders (BCryptPasswordEncoder, NoOpPasswordEncoder, Pbkdf2PasswordEncoder, SCryptPasswordEncoder, Argon2PasswordEncoder) |
| commons.go | JJWT (SignatureAlgorithm.HS256/HS512), Apache Commons Crypto |

### Python — 70 rules (`pkg/rules/python/pyca.go`)
**Bundle:** Pyca

Covers the full `cryptography` (pyca) library:
- Symmetric: AES, 3DES, Camellia, ChaCha20
- Cipher modes: CBC, CTR, GCM, SIV, CCM, OFB, CFB, XTS, ECB
- AEAD: ChaCha20Poly1305, AESGCM, AESOCB3, XChaCha20Poly1305
- Hash: SHA-1/2/3, BLAKE2b/s
- MAC: HMAC, CMAC, Poly1305
- Asymmetric: RSA (generate, encrypt, decrypt, sign, verify), EC keys, DSA, DH, Ed25519, X25519, Ed448, X448
- KDF: PBKDF2HMAC, Scrypt, HKDF, Argon2 (id/i/d), bcrypt
- TLS: SSLContext.wrap_socket
- Post-Quantum: ML-DSA, ML-KEM
- ECDH: .exchange(ECDH())
- RSA decrypt via private_key.decrypt()

### PHP — 60 rules (`pkg/rules/php/rules.go`)
**Bundles:** PhpBuiltin, PhpOpenSSL, PhpSodium, PhpPhpseclib, PhpJWT

Covers:
- Built-ins: openssl_encrypt/decrypt, openssl_sign/verify, openssl_get_cipher_methods, hash(), hash_hmac(), hash_pbkdf2(), password_hash(), password_verify(), random_bytes(), random_int(), md5(), sha1(), crypt(), hash_init()
- OpenSSL extensions: openssl_public_encrypt, openssl_private_decrypt, openssl_seal, openssl_open, openssl_pkcs7_sign, openssl_pkcs7_verify, openssl_csr_new
- Sodium: sodium_crypto_* (aead, secretbox, box, sign, hash, pwhash, kdf, scalarmult, auth, shorthash)
- phpseclib: AES, TripleDES, RSA, EC, DSA, DH, Blowfish, Twofish, RC4, ChaCha20, Salsa20
- firebase/php-jwt: JWT::encode, JWT::decode

### Ruby — 28 rules (`pkg/rules/ruby/rules.go`)
**Bundles:** RubyOpenSSL, RubyBuiltin, RubyBcrypt, RubyJWT

Covers:
- OpenSSL::Cipher (AES, 3DES, ChaCha20, RC2/4/5, IDEA), Digest, HMAC (.digest, .hexdigest, .base64digest)
- OpenSSL::PKey (RSA, EC, DSA, DH): generate, sign, sign_raw, verify, verify_raw, derive, dh_compute_key
- OpenSSL::KDF: pbkdf2_hmac, scrypt, hkdf
- OpenSSL::SSL: ssl_version=, min_version=, max_version=
- OpenSSL::PKCS5: pbkdf2_hmac_sha1
- Digest stdlib: SHA256, SHA512, SHA1, MD5, SHA384
- SecureRandom: hex, random_bytes, uuid, base64, alphanumeric
- BCrypt: Password.create, Password.new, Engine.hash_secret
- JWT gem: JWT.encode, JWT.decode

### Dart/Flutter — 31 rules (`pkg/rules/flutter/cryptography.go`)
**Bundles:** FlutterCrypto, FlutterPointyCastle, FlutterEncrypt, FlutterTLS, DartCrypto, FlutterJWT

Covers: package:crypto, package:cryptography, package:pointycastle, package:encrypt, dart:io TLS, dart:math Random.secure(), JWT libraries

### C# — 46 rules (`pkg/rules/csharp/rules.go`)
Covers: System.Security.Cryptography (Aes, DES, TripleDES, RC2, RSA, ECDSA, SHA*, HMAC*, RijndaelManaged, etc.), .NET TLS/SSL

### JavaScript/TypeScript — 39 rules (`pkg/rules/javascript/rules.go`)
Covers: Node.js crypto module, Web Crypto API, jose, jsonwebtoken, crypto-js, bcryptjs, tweetnacl

### Rust — 39 rules (`pkg/rules/rust/rules.go`)
Covers: ring, rust-crypto, aes, sha2, ed25519-dalek, x25519-dalek, chacha20poly1305, argon2, pbkdf2, bcrypt, rustls, openssl crate

---

## 8. Vulnerability Rules (49 rules) — `pkg/vulndb/rules.go`

Format: `CBOM-{CATEGORY}-{NNN}` — Severity: critical / high / medium / low / info

### Hash (CBOM-HASH-*)
| ID | Algorithm | Severity |
|----|-----------|----------|
| CBOM-HASH-001 | MD5 | critical |
| CBOM-HASH-002 | SHA-1 | high |
| CBOM-HASH-003 | MD4 | critical |
| CBOM-HASH-004 | MD2 | critical |
| CBOM-HASH-005 | RIPEMD-128/160 (when used for signatures) | medium |
| CBOM-HASH-006 | Whirlpool (non-standard) | info |

### Cipher (CBOM-CIPHER-*)
| ID | Algorithm | Severity |
|----|-----------|----------|
| CBOM-CIPHER-001 | DES | critical |
| CBOM-CIPHER-002 | 3DES / Triple-DES | high |
| CBOM-CIPHER-003 | RC4 | critical |
| CBOM-CIPHER-004 | RC2 | critical |
| CBOM-CIPHER-005 | Blowfish | medium |
| CBOM-CIPHER-006 | IDEA | medium |
| CBOM-CIPHER-007 | NullCipher | critical |

### Mode / Padding
| ID | Issue | Severity |
|----|-------|----------|
| CBOM-MODE-001 | ECB mode (no IV, pattern-leaking) | high |
| CBOM-PADDING-001 | PKCS1v15 encryption padding (RSA) | high |

### TLS (CBOM-TLS-*)
| ID | Issue | Severity |
|----|-------|----------|
| CBOM-TLS-001 | SSLv2 / SSLv3 | critical |
| CBOM-TLS-002 | TLS 1.0 | high |
| CBOM-TLS-003 | TLS 1.1 | medium |
| CBOM-TLS-004 | TLS configured without explicit minimum version | info |

### Cipher Suites (CBOM-SUITE-*)
| ID | Suite | Severity |
|----|-------|----------|
| CBOM-SUITE-001 | RC4-containing suites | critical |
| CBOM-SUITE-002 | DES/3DES suites (SWEET32) | high |
| CBOM-SUITE-003 | NULL cipher suites | critical |
| CBOM-SUITE-004 | EXPORT cipher suites | critical |
| CBOM-SUITE-005 | Anonymous (anon) suites | critical |
| CBOM-SUITE-006 | MD5-based suites | high |
| CBOM-SUITE-007 | Non-forward-secret suites (no ECDHE/DHE) | medium |

### Key Size (CBOM-KEY-*)
| ID | Issue | Severity |
|----|-------|----------|
| CBOM-KEY-001 | RSA key < 2048 bits | high |
| CBOM-KEY-002 | RSA key < 3072 bits (quantum-era concern) | medium |
| CBOM-KEY-003 | DSA key < 2048 bits | high |
| CBOM-KEY-004 | EC key on P-192 or smaller curve | high |

### Post-Quantum (CBOM-PQC-*)
| ID | Issue | Severity |
|----|-------|----------|
| CBOM-PQC-001 | RSA not quantum-safe — informational | info |
| CBOM-PQC-002 | ECDSA not quantum-safe — informational | info |
| CBOM-PQC-003 | DH/ECDH not quantum-safe — informational | info |
| CBOM-PQC-004 | Ed25519 not quantum-safe — informational | info |
| CBOM-PQC-005 | DSA not quantum-safe — informational | info |

### Other categories
| ID | Issue | Severity |
|----|-------|----------|
| CBOM-KDF-001 | Weak KDF (MD5 or SHA-1 based PBKDF2) | high |
| CBOM-KDF-002 | Insecure password hash (MD5/SHA-1 direct hash) | critical |
| CBOM-RNG-001 | Insecure PRNG (math/rand, java.util.Random) | high |
| CBOM-RNG-003 | Hardcoded/static IV or nonce | high |
| CBOM-NULL-001 | NullCipher / no encryption | critical |
| CBOM-IV-001 | IvParameterSpec usage (may indicate static IV) | medium |
| CBOM-KS-001 | Default KeyStore (JKS — weak format) | medium |
| CBOM-NATIONAL-001 | GOST (Russian national cipher) | info |
| CBOM-NATIONAL-002 | SM2/SM3/SM4 (Chinese national cipher) | info |
| CBOM-NATIONAL-003 | Camellia (non-standard in most contexts) | info |
| CBOM-CERT-001 | X.509 certificate with SHA-1 signature | high |
| CBOM-CERT-002 | X.509 certificate with MD5 signature | critical |
| CBOM-JWT-001 | JWT with `alg: none` (no signature) | critical |
| CBOM-JWT-002 | JWT with symmetric HS256/HS384/HS512 — review needed | medium |

---

## 9. VEX Rules (10 rules) — `pkg/vex/rules.go`

VEX rules produce exploitability assessments (not_affected / affected / under_investigation / fixed)
on top of vulnerability findings. They are strictly additive — they do not remove or modify
vulnerability findings, only add context.

VEX statuses: `not_affected` · `affected` · `under_investigation` · `fixed`

---

## 10. Output Format

### CBOM JSON (`cbom.json`) — CycloneDX 1.6

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2026-04-22T...",
    "tools": [{ "vendor": "cbom-scanner", "name": "cbom-scanner", "version": "0.1.0" }]
  },
  "components": [
    {
      "type": "crypto-asset",
      "bom-ref": "crypto-algorithm-AES-...",
      "name": "AES",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "mode": "GCM",
          "cryptoFunctions": ["encrypt", "decrypt"]
        }
      },
      "evidence": { "occurrences": [{ "location": "src/...", "line": 42 }] },
      "properties": [
        { "name": "bundle", "value": "GoStdlib" },
        { "name": "keyLength", "value": "256" },
        { "name": "matchedText", "value": "aes.NewCipher(" }
      ],
      "vulnerabilities": [{ "id": "CBOM-CIPHER-001", "severity": "critical" }],
      "vex": {
        "vulnerabilities": [{ "cve_id": "...", "vex_status": "not_affected", ... }]
      }
    }
  ],
  "dependencies": [...]
}
```

### Asset types in output
- `"algorithm"` — detected algorithm
- `"related-crypto-material"` — key (secret-key / public-key / private-key)
- `"protocol"` — TLS, SSH, cipher suite

---

## 11. How to Add a New Detection Rule

1. Open the language rule file, e.g. `pkg/rules/golang/stdlib.go`
2. Write a new function returning `*detection.Rule`:
   ```go
   func goMyNewRule() *detection.Rule {
       return &detection.Rule{
           ID:        "go-my-rule",           // unique, kebab-case
           Language:  detection.LangGo,
           Bundle:    "GoStdlib",              // library group
           Pattern:   regexp.MustCompile(`\bmyFunc\s*\(`),
           MatchType: detection.MatchFunctionCall,
           Extract: func(match []string, loc model.DetectionLocation) []model.INode {
               algo := model.NewAlgorithm("MyAlgo", model.PrimitiveAEAD, loc)
               algo.AddFunction(model.FuncEncrypt)
               return []model.INode{algo}
           },
       }
   }
   ```
3. Register it in `allGoRules()` (or the equivalent function for other languages)
4. Run `go build ./...` to verify no errors
5. Run `python update_rules_reference.py` to regenerate the Excel reference

---

## 12. How to Add a New Vulnerability Rule

Open `pkg/vulndb/rules.go` and add a `registry.Register(&VulnRule{...})` block:

```go
registry.Register(&VulnRule{
    ID:          "CBOM-CIPHER-008",
    Category:    "cipher",
    Title:       "My Weak Cipher",
    Description: "Explanation of the weakness.",
    Severity:    "high",        // critical|high|medium|low|info
    References:  []string{"RFC XXXX"},
    Recommendation: "Replace with AES-256-GCM.",
    Match: func(node model.INode) bool {
        a, ok := node.(*model.Algorithm)
        return ok && strings.EqualFold(a.Name, "MyWeakCipher")
    },
})
```

---

## 13. Key Repositories Analysed (for rule additions)

| Repo | Language | Rules Added |
|------|----------|-------------|
| pyca/cryptography | Python | 9 new rules + 2 bug fixes |
| WebGoat | Java | Confirmed coverage via JCA/Spring rules |
| laravel/framework | PHP | 14 new rules |
| heartcombo/devise | Ruby | 2 new rules (BCrypt patterns) |
| ruby/openssl | Ruby | 7 new rules + 2 bug fixes |
| hashicorp/vault | Go | 5 new rules (Shamir, TOTP, HOTP, AES-CMAC, X25519MLKEM768) |
| caddyserver/caddy | Go | 8 new rules (TLS curves, X25519MLKEM768, x509 ops, math/rand) |

---

## 14. Regenerating the Rules Reference Excel

```bash
# From project root
python update_rules_reference.py
# Output: cbom_rules_reference.xlsx (also copied to Desktop on demand)
```

The Excel has:
- **All Rules** sheet — all 423 rules colour-coded by language
- **Summary by Language** sheet — rule count per language
- One **per-language sheet** for each of the 9 languages

---

## 15. Bundle Name Reference

| Bundle | Language | What it covers |
|--------|----------|----------------|
| GoStdlib | Go | crypto/*, crypto/tls, crypto/x509, math/rand |
| GoXCrypto | Go | golang.org/x/crypto (argon2, bcrypt, blake2, chacha20, nacl, hkdf, scrypt) |
| GoJWT | Go | github.com/golang-jwt/jwt, github.com/dgrijalva/jwt-go |
| GoVault | Go | github.com/hashicorp/vault/shamir |
| GoOTP | Go | github.com/pquerna/otp (TOTP/HOTP) |
| GoTink | Go | github.com/tink-crypto/tink-go (AES-CMAC) |
| JCA | Java | Java Cryptography Architecture (javax.crypto, java.security) |
| BouncyCastle | Java | org.bouncycastle.* |
| Spring | Java | org.springframework.security.crypto.* |
| Commons | Java | JJWT, Apache Commons Crypto |
| Pyca | Python | cryptography (pyca/cryptography) |
| PhpBuiltin | PHP | PHP built-in crypto functions (openssl_*, hash*, password_*) |
| PhpOpenSSL | PHP | OpenSSL-specific PHP functions |
| PhpSodium | PHP | sodium_* extension |
| PhpPhpseclib | PHP | phpseclib library |
| PhpJWT | PHP | firebase/php-jwt |
| RubyOpenSSL | Ruby | OpenSSL:: module |
| RubyBuiltin | Ruby | Digest::, SecureRandom:: stdlib |
| RubyBcrypt | Ruby | bcrypt gem |
| RubyJWT | Ruby | jwt gem |
| FlutterCrypto | Dart | package:crypto, package:cryptography |
| FlutterPointyCastle | Dart | package:pointycastle |
| FlutterEncrypt | Dart | package:encrypt |
| FlutterTLS | Dart | dart:io TLS |
| DartCrypto | Dart | dart:math Random.secure() |
| FlutterJWT | Dart | JWT libraries |
