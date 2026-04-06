package detection

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/cbom-scanner/pkg/model"
)

// Finding represents a single detected cryptographic asset with its source location.
type Finding struct {
	Nodes []model.INode
	Rule  *Rule
}

// ScanResult holds all findings from scanning a project.
type ScanResult struct {
	Findings []Finding
	Errors   []error
}

// Engine is the main detection engine that scans source files for crypto usage.
type Engine struct {
	registry *RuleRegistry
}

func NewEngine(registry *RuleRegistry) *Engine {
	return &Engine{registry: registry}
}

// ScanDirectory recursively scans a directory for crypto assets.
func (e *Engine) ScanDirectory(root string) *ScanResult {
	result := &ScanResult{}

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, err)
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			// Skip common non-source directories
			if base == ".git" || base == "node_modules" || base == "__pycache__" ||
				base == "vendor" || base == "target" || base == "build" || base == ".idea" {
				return filepath.SkipDir
			}
			return nil
		}

		lang := languageFromExt(path)
		if lang == "" {
			return nil
		}

		findings, err := e.ScanFile(path, lang)
		if err != nil {
			result.Errors = append(result.Errors, err)
			return nil
		}
		result.Findings = append(result.Findings, findings...)
		return nil
	})

	return result
}

// ScanFile scans a single file for crypto assets.
func (e *Engine) ScanFile(filePath string, lang Language) ([]Finding, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rules := e.registry.RulesForLanguage(lang)
	if len(rules) == 0 {
		return nil, nil
	}

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range rules {
			matches := rule.Pattern.FindStringSubmatch(line)
			if matches == nil {
				continue
			}

			loc := model.DetectionLocation{
				FilePath: filePath,
				Line:     lineNum,
				Column:   strings.Index(line, matches[0]) + 1,
				Bundle:   rule.Bundle,
			}

			nodes := rule.Extract(matches, loc)
			if len(nodes) > 0 {
				findings = append(findings, Finding{
					Nodes: nodes,
					Rule:  rule,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return findings, err
	}

	return findings, nil
}

func languageFromExt(path string) Language {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".java":
		return LangJava
	case ".py":
		return LangPython
	case ".go":
		return LangGo
	default:
		return ""
	}
}
