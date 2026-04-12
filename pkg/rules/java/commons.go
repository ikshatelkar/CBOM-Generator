package java

import (
	"regexp"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterCommonsDetectionRules registers Java detection rules for:
//   - Apache Commons Codec (DigestUtils)
//   - Google Guava (Hashing)
//   - JJWT (io.jsonwebtoken)
//   - Nimbus JOSE+JWT
//   - javax.net.ssl.SSLSocket setEnabledProtocols / setEnabledCipherSuites
func RegisterCommonsDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range commonsRules() {
		registry.Register(r)
	}
}

func commonsRules() []*detection.Rule {
	return []*detection.Rule{
		// Apache Commons Codec
		commonsDigestUtils(),
		// Google Guava
		guavaHashing(),
		// JJWT
		jjwtSignWith(),
		jjwtParserAlgorithm(),
		// Nimbus JOSE+JWT
		nimbusJWSHeader(),
		nimbusJWEHeader(),
		// javax.net.ssl.SSLSocket
		sslSocketSetEnabledProtocols(),
		sslSocketSetEnabledCipherSuites(),
	}
}

// --- Apache Commons Codec: DigestUtils ---
// Detects DigestUtils.md5Hex(...), DigestUtils.sha1Hex(...), DigestUtils.sha256Hex(...)
// etc. from commons-codec and commons-lang3.

func commonsDigestUtils() *detection.Rule {
	return &detection.Rule{
		ID:       "commons-digest-utils",
		Language: detection.LangJava,
		Bundle:   "ApacheCommons",
		Pattern: regexp.MustCompile(
			`DigestUtils\s*\.\s*(md5|md5Hex|sha|sha1|sha1Hex|sha256|sha256Hex|sha384|sha384Hex|sha512|sha512Hex|shaHex|sha3_256Hex|sha3_512Hex)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeDigestUtilsName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func normalizeDigestUtilsName(method string) string {
	switch {
	case len(method) >= 3 && method[:3] == "md5":
		return "MD5"
	case method == "sha" || method == "shaHex" || method == "sha1" || method == "sha1Hex":
		return "SHA-1"
	case method == "sha256" || method == "sha256Hex":
		return "SHA-256"
	case method == "sha384" || method == "sha384Hex":
		return "SHA-384"
	case method == "sha512" || method == "sha512Hex":
		return "SHA-512"
	case method == "sha3_256Hex":
		return "SHA3-256"
	case method == "sha3_512Hex":
		return "SHA3-512"
	default:
		return method
	}
}

// --- Google Guava: Hashing ---
// Detects Hashing.md5(), Hashing.sha1(), Hashing.sha256(), Hashing.sha512(), etc.

func guavaHashing() *detection.Rule {
	return &detection.Rule{
		ID:       "guava-hashing",
		Language: detection.LangJava,
		Bundle:   "Guava",
		Pattern: regexp.MustCompile(
			`Hashing\s*\.\s*(md5|sha1|sha256|sha384|sha512|sha512_256|adler32|crc32|murmur3_32|murmur3_128|sipHash24|goodFastHash|farmHashFingerprint64)\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := normalizeGuavaHashName(match[1])
			algo := model.NewAlgorithm(name, model.PrimitiveHash, loc)
			algo.AddFunction(model.FuncDigest)
			return []model.INode{algo}
		},
	}
}

func normalizeGuavaHashName(method string) string {
	switch method {
	case "md5":
		return "MD5"
	case "sha1":
		return "SHA-1"
	case "sha256":
		return "SHA-256"
	case "sha384":
		return "SHA-384"
	case "sha512":
		return "SHA-512"
	case "sha512_256":
		return "SHA-512/256"
	default:
		return method
	}
}

// --- JJWT: Jwts.builder().signWith(key, SignatureAlgorithm.XXX) ---
// Also detects Jwts.builder().signWith(key) without algorithm (defaults to HS256 or
// allows none) and the legacy signWith(SignatureAlgorithm.NONE, ...) call.

func jjwtSignWith() *detection.Rule {
	return &detection.Rule{
		ID:       "jjwt-sign-with",
		Language: detection.LangJava,
		Bundle:   "JJWT",
		Pattern: regexp.MustCompile(
			`SignatureAlgorithm\s*\.\s*(HS256|HS384|HS512|RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|NONE|none)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := jwtAlgorithmPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// jjwtParserAlgorithm detects algorithms passed to Jwts.parserBuilder().setAllowedClockSkewSeconds
// and more importantly .require(Claims.SUBJECT) chained after verifyWith — the
// key pattern is .parseClaimsJws / .parseClaimsJwt without signature validation
// which accepts the JWT `none` algorithm attack.

func jjwtParserAlgorithm() *detection.Rule {
	return &detection.Rule{
		ID:       "jjwt-parse-none",
		Language: detection.LangJava,
		Bundle:   "JJWT",
		// Detects parseClaimsJwt (without 's') — this accepts unsigned (none) JWTs
		Pattern: regexp.MustCompile(`\.\s*parseClaimsJwt\s*\(`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("none", model.PrimitiveSignature, loc)
			algo.AddFunction(model.FuncVerify)
			loc.MatchedText = loc.MatchedText + " [JWT none: unsigned token accepted]"
			return []model.INode{algo}
		},
	}
}

// --- Nimbus JOSE+JWT: new JWSHeader(JWSAlgorithm.XXX) ---

func nimbusJWSHeader() *detection.Rule {
	return &detection.Rule{
		ID:       "nimbus-jws-header",
		Language: detection.LangJava,
		Bundle:   "NimbusJOSE",
		Pattern: regexp.MustCompile(
			`JWSAlgorithm\s*\.\s*(HS256|HS384|HS512|RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|EdDSA|ES256K|NONE|none)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			name := match[1]
			prim := jwtAlgorithmPrimitive(name)
			algo := model.NewAlgorithm(name, prim, loc)
			algo.AddFunction(model.FuncSign)
			return []model.INode{algo}
		},
	}
}

// --- Nimbus JOSE+JWT: JWEAlgorithm / EncryptionMethod ---

func nimbusJWEHeader() *detection.Rule {
	return &detection.Rule{
		ID:       "nimbus-jwe-header",
		Language: detection.LangJava,
		Bundle:   "NimbusJOSE",
		Pattern: regexp.MustCompile(
			`JWEAlgorithm\s*\.\s*(RSA1_5|RSA_OAEP|RSA_OAEP_256|A128KW|A192KW|A256KW|DIR|ECDH_ES|ECDH_ES_A128KW|ECDH_ES_A192KW|ECDH_ES_A256KW|A128GCMKW|A192GCMKW|A256GCMKW|PBES2_HS256_A128KW|PBES2_HS384_A192KW|PBES2_HS512_A256KW)`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			algo := model.NewAlgorithm(match[1], model.PrimitivePublicKeyEncryption, loc)
			algo.AddFunction(model.FuncEncrypt)
			return []model.INode{algo}
		},
	}
}

// --- javax.net.ssl.SSLSocket: setEnabledProtocols ---
// Detects explicit protocol arrays passed to setEnabledProtocols.
// e.g. socket.setEnabledProtocols(new String[]{"SSLv3", "TLSv1"})

func sslSocketSetEnabledProtocols() *detection.Rule {
	return &detection.Rule{
		ID:       "ssl-socket-enabled-protocols",
		Language: detection.LangJava,
		Bundle:   "JSSE",
		Pattern: regexp.MustCompile(
			`setEnabledProtocols\s*\(\s*new\s+String\s*\[\s*\]\s*\{([^}]+)\}`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			// Extract each quoted protocol string from the array literal
			protoPattern := regexp.MustCompile(`"([^"]+)"`)
			protos := protoPattern.FindAllStringSubmatch(match[1], -1)
			var nodes []model.INode
			for _, p := range protos {
				if len(p) < 2 {
					continue
				}
				proto := model.NewProtocol(p[1], loc)
				nodes = append(nodes, proto)
			}
			return nodes
		},
	}
}

// --- javax.net.ssl.SSLSocket: setEnabledCipherSuites ---
// Detects explicit cipher suite arrays passed to setEnabledCipherSuites.

func sslSocketSetEnabledCipherSuites() *detection.Rule {
	return &detection.Rule{
		ID:       "ssl-socket-enabled-suites",
		Language: detection.LangJava,
		Bundle:   "JSSE",
		Pattern: regexp.MustCompile(
			`setEnabledCipherSuites\s*\(\s*new\s+String\s*\[\s*\]\s*\{([^}]+)\}`),
		MatchType: detection.MatchMethodCall,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			if len(match) < 2 {
				return nil
			}
			suitePattern := regexp.MustCompile(`"([^"]+)"`)
			suites := suitePattern.FindAllStringSubmatch(match[1], -1)
			var nodes []model.INode
			for _, s := range suites {
				if len(s) < 2 {
					continue
				}
				suite := model.NewCipherSuite(s[1], loc)
				nodes = append(nodes, suite)
			}
			return nodes
		},
	}
}

// jwtAlgorithmPrimitive maps a JWT algorithm name to the appropriate model primitive.
func jwtAlgorithmPrimitive(alg string) model.Primitive {
	switch {
	case alg == "NONE" || alg == "none":
		return model.PrimitiveSignature // "no signature" — still a signature primitive slot
	case len(alg) >= 2 && alg[:2] == "HS":
		return model.PrimitiveMAC // HMAC-based
	case len(alg) >= 2 && alg[:2] == "RS":
		return model.PrimitiveSignature // RSA PKCS1
	case len(alg) >= 2 && alg[:2] == "PS":
		return model.PrimitiveSignature // RSA-PSS
	case len(alg) >= 2 && alg[:2] == "ES":
		return model.PrimitiveSignature // ECDSA
	case alg == "EdDSA":
		return model.PrimitiveSignature
	default:
		return model.PrimitiveUnknown
	}
}
