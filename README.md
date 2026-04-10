# cbom-scanner

A standalone CLI tool that scans source code for cryptographic assets, detects known vulnerabilities, and generates a **Cryptographic Bill of Materials (CBOM)** in [CycloneDX 1.6](https://cyclonedx.org/) format.

---

## What It Does

The scanner reads every Java and Python source file in a target directory, identifies every place cryptography is used (algorithms, keys, protocols), checks each one against a library of known vulnerability rules, and produces a structured report. The output tells you exactly what crypto is in your codebase, where it is, and which parts are a security risk.

---

## Features

### Detection
- **Java** — JCA standard library, BouncyCastle, Spring Security password encoders
- **Python** — pyca/cryptography, Python stdlib (hashlib, hmac), PyCryptodome, PyNaCl, PyJWT, liboqs (post-quantum)
- **76 detection rules** across both languages
- Concurrent file scanning using a goroutine worker pool
- `matchedText` property on every CBOM asset — shows the exact source code text that triggered detection

### Vulnerability Analysis
- **42 vulnerability rules** covering weak algorithms, broken modes, insecure protocols, short key sizes, deprecated keystores, and post-quantum readiness
- Severity levels: `critical`, `high`, `medium`, `low`, `info`
- ECB mode inference — `Cipher.getInstance("AES")` with no mode specified is automatically flagged as ECB

### VEX (Vulnerability Exploitability eXchange)
- Additive exploitability assessment layer on top of vulnerability findings
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
| `--fail-on` | _(none)_ | Exit code 1 if any vuln at or above this severity is found (`critical\|high\|medium\|low\|info`) |
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
- **`matchedText`** — the exact source code expression that was matched (e.g. `Cipher.getInstance("AES/ECB/PKCS5Padding")`)
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
│   ├── java/
│   │   ├── jca.go       Java Cryptography Architecture (17 rules)
│   │   ├── bouncycastle.go  BouncyCastle library (10 rules)
│   │   └── spring.go    Spring Security password encoders (6 rules)
│   └── python/
│       └── pyca.go      All Python rules — pyca, stdlib, PyCryptodome,
│                        PyNaCl, PyJWT, liboqs (43 rules)
├── enricher/            Adds OIDs, key lengths, digest sizes, block sizes
├── analyzer/            Matches detected assets against vulnerability rules
├── vulndb/              42 vulnerability rules (rule.go + rules.go)
├── vex/                 VEX evaluation layer (rule.go + rules.go + evaluator.go)
└── output/
    ├── cyclonedx.go     CycloneDX 1.6 CBOM generator
    ├── sarif.go         SARIF 2.1.0 report generator
    └── report.go        Terminal asset report table
```

---

## Detection Rules

### Java — 33 rules

**JCA (17 rules):** `Cipher.getInstance`, `MessageDigest.getInstance`, `Signature.getInstance`, `Mac.getInstance`, `KeyGenerator.getInstance`, `KeyPairGenerator.getInstance`, `new SecretKeySpec`, `KeyFactory.getInstance`, `KeyAgreement.getInstance`, `SSLContext.getInstance`, `SecretKeyFactory.getInstance`, `SecureRandom.getInstance`, `new SecureRandom()`, `SecureRandom.getInstanceStrong()`, `new NullCipher()`, `new IvParameterSpec(new byte[...])`, `KeyStore.getInstance`

**BouncyCastle (10 rules):** Block cipher engines, stream ciphers, AEAD ciphers, digests, MACs, key generators, signers, key pair generators, key agreement, PBE parameter generators

**Spring Security (6 rules):** `MD5PasswordEncoder`, `ShaPasswordEncoder`, `BCryptPasswordEncoder`, `Argon2PasswordEncoder`, `Pbkdf2PasswordEncoder`, `SCryptPasswordEncoder`

### Python — 43 rules

**pyca/cryptography (26 rules):** Symmetric algorithms, cipher modes, AEAD ciphers, hash algorithms, HMAC, CMAC, RSA/EC/DSA/DH key generation, Ed25519, Ed448, X25519, X448, KDFs (PBKDF2, HKDF, Scrypt), Fernet, RSA/EC signing, RSA encryption, cipher suites, SSL context, `os.urandom`, `secrets`, BLAKE3, liboqs KEM, liboqs signature

**Python stdlib (4 rules):** `hashlib.<algo>()`, `hashlib.new()`, `hashlib.pbkdf2_hmac()`, `hmac.new()`

**PyCryptodome (8 rules):** `AES.new`, symmetric ciphers, hash algorithms, `RSA.generate`, `ECC.generate`, PKCS1 padding, `HMAC.new`, KDFs

**PyNaCl (3 rules):** `SigningKey.generate` (Ed25519), `SecretBox` (XSalsa20-Poly1305), `Box` (Curve25519)

**PyJWT (2 rules):** `jwt.encode`, `jwt.decode`

---

## Vulnerability Rules (42 total)

| Category | Rules | Examples |
|---|---|---|
| Hash | 5 | MD5, SHA-1, MD5 in signatures, SHA-1 MACs |
| Symmetric cipher | 5 | DES, RC4, ECB mode, 3DES, weak key size |
| Padding | 1 | PKCS#1 v1.5 |
| Protocol | 6 | SSLv2, SSLv3, TLS 1.0, TLS 1.1, weak cipher suites |
| Key size | 5 | RSA < 2048, DSA < 2048, EC < 224, DH < 2048 |
| RNG | 1 | SHA1PRNG |
| KDF | 2 | Weak PBE, PBKDF2 with weak hash |
| CWE-1240 | 3 | NullCipher, hardcoded zero IV, weak PBE schemes |
| Keystore | 1 | Deprecated JKS format |
| National algo | 1 | GOST (RFC 7696) |
| Post-quantum | 7 | RSA, EC, DH, DSA, AES-128, AES-256, general PQC |

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

Then add it to the relevant `*Rules()` slice and register it in `main.go`.

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
