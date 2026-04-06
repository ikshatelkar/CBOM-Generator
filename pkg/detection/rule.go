package detection

import (
	"regexp"

	"github.com/cbom-scanner/pkg/model"
)

// Language identifies the source language being scanned.
type Language string

const (
	LangJava   Language = "java"
	LangPython Language = "python"
	LangGo     Language = "go"
)

// MatchType indicates how a rule matches source lines.
type MatchType int

const (
	MatchMethodCall   MatchType = iota // e.g. Cipher.getInstance(...)
	MatchConstructor                   // e.g. new SecretKeySpec(...)
	MatchImport                        // e.g. from cryptography.hazmat... import ...
	MatchFunctionCall                  // e.g. algorithms.AES(key)
)

// Rule defines a single crypto detection pattern.
type Rule struct {
	ID        string         // unique rule identifier
	Language  Language       // which language this rule applies to
	Bundle    string         // library bundle: "JCA", "BouncyCastle", "Pyca", etc.
	Pattern   *regexp.Regexp // compiled regex to match source lines
	MatchType MatchType      // what kind of match this is
	Extract   ExtractFunc    // extracts crypto info from a regex match
	DependsOn []string       // IDs of parent rules (for chained detection)
}

// ExtractFunc takes a regex match and the matched line, returns detected nodes.
// Groups from the regex are passed as the submatch slice.
type ExtractFunc func(match []string, loc model.DetectionLocation) []model.INode

// RuleRegistry holds all detection rules organized by language.
type RuleRegistry struct {
	rules map[Language][]*Rule
}

func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{rules: make(map[Language][]*Rule)}
}

func (r *RuleRegistry) Register(rule *Rule) {
	r.rules[rule.Language] = append(r.rules[rule.Language], rule)
}

func (r *RuleRegistry) RulesForLanguage(lang Language) []*Rule {
	return r.rules[lang]
}

func (r *RuleRegistry) AllRules() []*Rule {
	var all []*Rule
	for _, rules := range r.rules {
		all = append(all, rules...)
	}
	return all
}
