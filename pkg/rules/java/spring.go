package java

import (
	"regexp"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/model"
)

// RegisterSpringDetectionRules registers Spring Security password encoder detection rules.
// Spring Security password encoders are the standard way to hash passwords in Spring
// applications. Detecting them lets the CBOM capture what password hashing scheme is
// in use and flag deprecated ones (MD5, SHA-1) as vulnerabilities.
func RegisterSpringDetectionRules(registry *detection.RuleRegistry) {
	for _, r := range springRules() {
		registry.Register(r)
	}
}

func springRules() []*detection.Rule {
	return []*detection.Rule{
		springMD5PasswordEncoder(),
		springSHAPasswordEncoder(),
		springBCryptPasswordEncoder(),
		springArgon2PasswordEncoder(),
		springPBKDF2PasswordEncoder(),
		springSCryptPasswordEncoder(),
	}
}

// --- new MD5PasswordEncoder() — deprecated, broken ---
// Uses raw MD5 which is collision-vulnerable and trivially brute-forced.
// Removed from Spring Security 5.8+.

func springMD5PasswordEncoder() *detection.Rule {
	return &detection.Rule{
		ID:        "spring-md5-password-encoder",
		Language:  detection.LangJava,
		Bundle:    "Spring",
		Pattern:   regexp.MustCompile(`new\s+MD5PasswordEncoder\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("MD5", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- new ShaPasswordEncoder() — deprecated, weak ---
// Uses raw SHA-1 (or SHA-256 if strength specified) without key-stretching.
// Deprecated since Spring Security 5.0.

func springSHAPasswordEncoder() *detection.Rule {
	return &detection.Rule{
		ID:        "spring-sha-password-encoder",
		Language:  detection.LangJava,
		Bundle:    "Spring",
		Pattern:   regexp.MustCompile(`new\s+ShaPasswordEncoder\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("SHA1", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- new BCryptPasswordEncoder() — recommended ---

func springBCryptPasswordEncoder() *detection.Rule {
	return &detection.Rule{
		ID:        "spring-bcrypt-password-encoder",
		Language:  detection.LangJava,
		Bundle:    "Spring",
		Pattern:   regexp.MustCompile(`new\s+BCryptPasswordEncoder\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("bcrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- new Argon2PasswordEncoder() — recommended (modern) ---

func springArgon2PasswordEncoder() *detection.Rule {
	return &detection.Rule{
		ID:        "spring-argon2-password-encoder",
		Language:  detection.LangJava,
		Bundle:    "Spring",
		Pattern:   regexp.MustCompile(`new\s+Argon2PasswordEncoder\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("Argon2", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- new Pbkdf2PasswordEncoder() ---

func springPBKDF2PasswordEncoder() *detection.Rule {
	return &detection.Rule{
		ID:        "spring-pbkdf2-password-encoder",
		Language:  detection.LangJava,
		Bundle:    "Spring",
		Pattern:   regexp.MustCompile(`new\s+Pbkdf2PasswordEncoder\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("PBKDF2", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}

// --- new SCryptPasswordEncoder() ---

func springSCryptPasswordEncoder() *detection.Rule {
	return &detection.Rule{
		ID:        "spring-scrypt-password-encoder",
		Language:  detection.LangJava,
		Bundle:    "Spring",
		Pattern:   regexp.MustCompile(`new\s+SCryptPasswordEncoder\s*\(`),
		MatchType: detection.MatchConstructor,
		Extract: func(match []string, loc model.DetectionLocation) []model.INode {
			algo := model.NewAlgorithm("scrypt", model.PrimitivePasswordHash, loc)
			algo.AddFunction(model.FuncKeyDerive)
			return []model.INode{algo}
		},
	}
}
