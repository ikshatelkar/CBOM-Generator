# CBOM Scanner — Development Log

> **Purpose:** A running daily journal of everything done on this project — work completed,
> bugs fixed, thoughts, what could have gone better, and ideas for the future.
> Add a new entry at the end of every working session.

---

## Entry 001 — Sessions 1–4 (Pre-May 2026)
### What We Built (Foundation)

The entire CBOM scanner was designed and implemented from scratch. Key milestones across the
early sessions:

- **Core engine** (`pkg/detection/engine.go`) — regex-based rule runner, scans files and dirs
- **Model layer** (`pkg/model/`) — `Algorithm`, `Protocol`, `CipherSuite`, `Key` nodes, all
  implementing `INode`
- **Rule registry** (`pkg/detection/rule.go`) — `Rule` struct with `ID`, `Language`, `Bundle`,
  `Pattern`, `MatchType`, `Extract`
- **Output format** — CycloneDX 1.6 JSON (CBOM), optional SARIF 2.1.0
- **10 languages** initially scaffolded: Go, Java, Python, JavaScript, TypeScript, C#, PHP,
  Ruby, Rust, Flutter/Dart

Rule files built:
- `golang/stdlib.go` — Go standard library + popular libraries
- `java/jca.go`, `java/bouncycastle.go`, `java/spring.go`, `java/commons.go`
- `python/pyca.go` — pyca/cryptography, PyCryptodome, PyNaCl, passlib, paramiko
- `javascript/rules.go` — Node.js crypto, Web Crypto, jose, jsonwebtoken, tweetnacl, crypto-js
- `csharp/rules.go` — .NET crypto, BouncyCastle .NET, JWT
- `php/rules.go` — openssl_*, sodium_*, phpseclib, firebase/php-jwt
- `ruby/rules.go` — OpenSSL, Digest, BCrypt gem, jwt gem
- `rust/rules.go` — ring, RustCrypto, rustls, argon2/bcrypt/scrypt
- `flutter/cryptography.go` — package:crypto, package:cryptography, PointyCastle, dart:io TLS

Vulnerability database (`pkg/vulndb/rules.go`) — ~49 rules across:
- HASH: MD5, SHA1 weak hash, CBOM-HASH-001..003
- SYM: DES, 3DES, RC4, ECB mode, weak key size
- ASYM: RSA < 2048, weak EC curves
- KDF: weak iteration count, weak salt, passlib weak hash
- TLS: SSL 2.0/3.0, TLS 1.0/1.1, NULL cipher, anonymous cipher, RC4 cipher
- JWT: none algorithm, HS256 weak secret
- RNG: SHA1PRNG, non-CSPRNG (CBOM-RNG-002)

---

## Entry 002 — Session 5 (April–May 2026)
### Repo Analysis: pyca/cryptography, WebGoat, Laravel, Devise, Ruby OpenSSL

**Work done:**
- Fetched and analysed 6 real-world repos to find gaps in our detection rules
- `pyca/cryptography` (Python): found and fixed 2 bugs (AESOCB3 typo, XChaCha20Poly1305 casing),
  added 7 new rules — ML-DSA, ML-KEM, Argon2, Poly1305, ECDH exchange, bcrypt, RSA decrypt
- `WebGoat` (Java): added `javaInsecureRandom()` for `java.util.Random` / `ThreadLocalRandom`
- `laravel/framework` (PHP): added 14 new PHP rules — `rand_bytes`, `sha1`, `md5`, `crypt`,
  `hash_init`, `openssl_public_encrypt`, `openssl_seal/open`, `openssl_pkcs7_sign/verify`,
  `sodium_crypto_scalarmult/auth/shorthash`, `firebase/php-jwt`, `password_verify`
- `heartcombo/devise` + `ruby/openssl` (Ruby): added 9 new Ruby rules — `PKey.generate_key`,
  `.sign/.verify/.derive`, `KDF.pbkdf2_hmac/scrypt/hkdf`, `ssl_version=`, BCrypt engine hash,
  fixed HMAC base64digest pattern
- Ran `go build ./...` and `go vet ./...` after each batch — zero errors

**Thoughts:**
- Real-repo analysis is the best way to find rule gaps. Static thinking about "what could exist"
  misses things you'd never guess until you see live code patterns.
- The pyca bug with `AESOCB3` vs `AESOCB3` would have silently never matched. Zero test coverage
  on regexes is a real risk — worth thinking about a regex unit test layer later.
- Laravel's PHP ecosystem has *way* more crypto surface than expected — `openssl_seal` is a
  multi-recipient asymmetric encryption function almost nobody talks about.

**What could have been better:**
- Should have built a test suite early. Every regex added without a test is a liability.
- The "add these 7 rules" → "build" cycle took multiple rounds of fixing const names
  (`FuncKeyAgreement` didn't exist → had to change to `FuncKeyDerive`). A simple
  `go build` before finalising each rule function would have saved time.

---

## Entry 003 — Session 6 (April–May 2026)
### Repo Analysis: hashicorp/vault, caddyserver/caddy + Go rule additions

**Work done:**
- Analysed `hashicorp/vault` and `caddyserver/caddy` for undetected Go crypto assets
- Added to `golang/stdlib.go`:
  - `goShamirSplit()` — Shamir's Secret Sharing (vault)
  - `goTOTPGenerate()`, `goHOTPGenerate()` — TOTP/HOTP via `pquerna/otp`
  - `goTinkAESCMAC()` — Google Tink AES-CMAC
  - `goX25519MLKEM768()` — Post-quantum hybrid TLS (vault)
  - `goTLSCurvePreferences()` — `tls.CurveP256/P384/P521/X25519`
  - `goX509CreateCertificate()`, `goX509ParseCertificate()` and variants
  - `goX509ParsePKCS8PrivateKey()`, `goX509ParsePKCS1PrivateKey()`, `goX509ParseECPrivateKey()`
  - `goX509MarshalPrivateKey()`, `goTLSLoadX509KeyPair()`
  - `goMathRandInsecure()` — `math/rand` usage flag

**Thoughts:**
- Vault's use of Google Tink was interesting — Tink is a high-level crypto library that wraps
  algorithms. Detecting it by the operation (AES-CMAC subtle call) rather than by import is the
  right approach for high-level libraries.
- Post-quantum crypto (X25519MLKEM768) showing up in production Go code is a signal that our
  scanner needs to keep pace with NIST standards as they land in ecosystems.
- Shamir's Secret Sharing is not "insecure" per se, but it is a crypto asset worth tracking in
  a CBOM — good call to add it.

**What could have been better:**
- Removed `goCertMagicKeyType()` when adding X.509 rules. Should have checked if it was used
  anywhere before deleting. Always grep for usages before removing functions.

---

## Entry 004 — Session 7 (April–May 2026)
### Excel reference, CBOM_PLAN.md, Debugging session

**Work done:**
- Created `update_rules_reference.py` — Python script that auto-extracts all rule IDs/bundles
  from Go files and generates `cbom_rules_reference.xlsx` (saved to Desktop too)
- Created `CBOM_PLAN.md` — comprehensive project reference file (528 lines) covering:
  architecture, all source files, detection rules, vuln rules, CLI flags, output format,
  how to extend the scanner
- Renamed `PROJECT_CONTEXT.md` → `CBOM_PLAN.md`
- **Debug session**: user made some modifications and asked to check for bugs. Found:
  - `CBOM-RNG-003` had wrong ID prefix (category was KDF, not RNG) → renamed to `CBOM-KDF-003`
  - `math/rand` detection rule existed but had no matching vuln rule → added `CBOM-RNG-002`
  - `math/rand` vuln rule wasn't firing (confirmed via runtime JSON inspection)
  - Fixed by adding CBOM-RNG-002 and checking the `Match` function logic

**Thoughts:**
- The rule ID mismatch (`CBOM-RNG-003` for a KDF rule) is exactly the kind of subtle bug that
  only surfaces when someone reads the output carefully. The naming convention (ID prefix matches
  category) needs to be a hard convention going forward.
- Runtime JSON inspection as a debugging technique works well — scanning a test file and reading
  the output CBOM tells you exactly what fired and what didn't. More systematic than print debugging.
- The Excel reference is genuinely useful — being able to see all 423 rules at a glance, filtered
  by language or bundle, is a much better audit tool than reading Go files.

**What could have been better:**
- Vuln rules should have corresponding detection rule IDs listed so it's clear what fires what.
  Currently you have to trace by algorithm name string — fragile.
- The PowerShell `&&` issue keeps coming up. Should just always use separate Shell calls or
  semicolons from now on. Noted.

---

## Entry 005 — Session 8 (May 7, 2026)
### Cross-language gap analysis + 6 new rules + Git push

**Work done:**

Systematically compared Python's rule coverage (used as "gold standard" since it's the most
complete) against every other language. Method:
- Ran targeted `Grep` searches per primitive category across all rule files
- Checked: CMAC, Poly1305, Ed448/X448, ML-DSA/ML-KEM, DH, SSH, scrypt, Argon2, Poly1305,
  BLAKE, HKDF, ECDH, cipher modes, PKCS1/7, KeyStore/X509, TOTP/HOTP, JWT, bcrypt,
  TLS/SSL, PBKDF2, insecure PRNG — across all 9 language rule sets

**Gaps found and fixed (6 new detection rules):**
- `py-random-insecure` — Python `random.random()`, `random.randint()`, etc. (Mersenne Twister,
  not a CSPRNG). Ironic that the gold-standard language was missing its own insecure PRNG.
- `cs-random-insecure` — C# `new System.Random()` non-CSPRNG
- `cs-hkdf` — C# `HKDF.DeriveKey/Extract/Expand` (.NET 5+) — was completely missing
- `cs-bcrypt-net` — C# `BCrypt.Net.BCrypt.HashPassword/VerifyPassword` — popular .NET library
- `php-rand-insecure` — PHP `rand()`, `mt_rand()`, `lcg_value()` — non-CSPRNGs
- `ruby-argon2` — Ruby `Argon2::Password.create/verify_password` — the argon2 gem

**Vuln rule updated:**
- `CBOM-RNG-002` — added Python `random.random`, C# `System.Random` to the match list,
  updated description and recommendation to cover all 9 languages

**Build result:** `go build ./...` and `go vet ./...` both clean, zero warnings.

**Git:** Committed and pushed to `origin/main` as `884bdc7`
- 15 files changed, 3592 insertions, 98 deletions

**Acceptable gaps identified (no action needed):**
- Ed448/X448 — only Python + Java (BouncyCastle) have first-class support in their ecosystems
- Post-quantum (ML-DSA/ML-KEM) — only Python, Go, C#/.NET 9 have stable APIs
- SSH (paramiko) — Python-specific library context
- Fernet — Python-specific; Dart's `package:encrypt` already covers it
- CMAC — not widely available as a standalone API in JS, Ruby, or PHP standard libs
- DSA in Rust — being phased out of the ecosystem, acceptable omission

**Thoughts:**
- Python missing its own `random` module detection was a funny find. We were using Python as
  the "everything is covered" benchmark and it had this blind spot. Goes to show that even the
  reference language needs auditing.
- C# had three gaps in one: insecure PRNG, HKDF, and BCrypt.Net. HKDF in .NET has been around
  since .NET 5 (2020) — this should have been in the initial C# rule set. Lesson: when adding
  rules for a language, check the *changelog* for that language's crypto APIs, not just the
  current docs.
- The PHP insecure PRNG (`rand()` / `mt_rand()`) is a classic CWE-338 issue that's incredibly
  common in older PHP codebases. With `phpRandomBytes()` and `phpRandomInt()` already in our
  rules, we were catching the secure alternative but not flagging the insecure one. That asymmetry
  is a pattern worth checking for in all languages — if we detect the safe version, we should
  also detect the unsafe version.
- First compile attempt failed because I used `model.PrimitiveKDF` and `model.FuncDerive` which
  don't exist — the correct constants are `model.PrimitiveKeyDerivation` and `model.FuncKeyDerive`.
  This is the second time this type of error has occurred. Should build a quick reference of all
  valid model constants into CBOM_PLAN.md.

**What could have been better:**
- The model constant names are inconsistent: `PrimitiveBlockCipher` vs `PrimitiveKeyDerivation`
  (one is short, one is long). Should have a `pkg/model/constants.go` or similar with a comment
  block listing all valid values — would save lookup time every time a new rule is added.
- The gap analysis was manual (grep per primitive). A better approach would be a script that:
  1. Extracts all unique primitive types per language from the rule `Extract` functions
  2. Produces a matrix: language × primitive → covered/missing
  This would make future gap analyses instant and reproducible.
- Committing all sessions' changes in one giant commit is messy. Would be cleaner to commit after
  each logical batch (e.g., one commit per language fix). The commit message had to summarise
  many things across many sessions.

**Ideas / future work:**
- [ ] Build the primitive coverage matrix script (language × primitive type grid)
- [ ] Add model constant reference to `CBOM_PLAN.md`
- [ ] Add regex unit tests — at minimum one positive and one negative test per rule
- [ ] Add a "last updated" timestamp to CBOM_PLAN.md so we know if it's stale
- [ ] Consider adding a severity level to detection rules (not just vuln rules) so the output
      CBOM can distinguish "this is a legacy weak cipher" from "this is a modern safe primitive"
- [ ] Look into whether `goTOTPGenerate` should fire a medium-severity vuln rule if the TOTP
      secret key is derived from a weak source (currently we detect the primitive but not the
      key derivation quality)

---

<!-- Add new entries below this line, newest at bottom -->
