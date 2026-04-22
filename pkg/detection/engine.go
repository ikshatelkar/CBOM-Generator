package detection

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

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
	// Workers controls the size of the goroutine pool used during directory
	// scans. Defaults to runtime.NumCPU() when zero or negative.
	Workers int
}

func NewEngine(registry *RuleRegistry) *Engine {
	return &Engine{registry: registry}
}

// ScanDirectory recursively scans a directory for crypto assets using a
// concurrent worker pool. The directory walk is performed sequentially to
// collect file paths, then each file is scanned in parallel.
func (e *Engine) ScanDirectory(root string) *ScanResult {
	result := &ScanResult{}

	// Phase 1: collect eligible file paths via a sequential walk.
	// Walk itself is I/O-bound on the FS metadata layer and is not easily
	// parallelised, but it is fast relative to parsing file contents.
	var filePaths []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, err)
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "__pycache__" ||
				base == "vendor" || base == "target" || base == "build" || base == ".idea" {
				return filepath.SkipDir
			}
			return nil
		}
		if languageFromExt(path) != "" {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	if len(filePaths) == 0 {
		return result
	}

	// Phase 2: fan out file scanning across a worker pool.
	numWorkers := e.Workers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > len(filePaths) {
		numWorkers = len(filePaths)
	}

	type fileResult struct {
		findings []Finding
		err      error
	}

	pathCh := make(chan string, len(filePaths))
	resultCh := make(chan fileResult, len(filePaths))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathCh {
				lang := languageFromExt(path)
				findings, err := e.ScanFile(path, lang)
				resultCh <- fileResult{findings: findings, err: err}
			}
		}()
	}

	for _, p := range filePaths {
		pathCh <- p
	}
	close(pathCh)

	// Close resultCh once all workers have finished so the collector loop below
	// can terminate cleanly.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Phase 3: collect results.
	for r := range resultCh {
		if r.err != nil {
			result.Errors = append(result.Errors, r.err)
		}
		result.Findings = append(result.Findings, r.findings...)
	}

	return result
}

// ScanFile scans a single file for crypto assets.
// It is safe to call from multiple goroutines concurrently.
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
	inBlockComment := false

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Strip comments before running detection rules so that
		// commented-out code never produces false-positive findings.
		codeLine, newInBlock := stripComments(raw, lang, inBlockComment)
		inBlockComment = newInBlock
		if strings.TrimSpace(codeLine) == "" {
			continue
		}

		for _, rule := range rules {
			matches := rule.Pattern.FindStringSubmatch(codeLine)
			if matches == nil {
				continue
			}

			loc := model.DetectionLocation{
				FilePath:    filePath,
				Line:        lineNum,
				Column:      strings.Index(codeLine, matches[0]) + 1,
				Bundle:      rule.Bundle,
				MatchedText: matches[0],
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

// stripComments removes the comment portion of a source line and returns the
// remaining code text together with the updated block-comment state.
//
// It handles:
//   - C-style line comments  (//)  used by Java, Go, JS/TS, C#, Dart, Rust, PHP
//   - Hash line comments     (#)   used by Python, Ruby, PHP
//   - C-style block comments (/* … */) tracked across lines
//   - Python/Ruby full-line comments only (# at start of code portion)
//
// The function is conservative: when in doubt it keeps the code text so that
// real detections are never silently dropped.
func stripComments(line string, lang Language, inBlock bool) (code string, stillInBlock bool) {
	// ── Block comment tracking (/* … */) ─────────────────────────────────────
	// Languages that use C-style block comments.
	usesCBlock := lang == LangJava || lang == LangGo || lang == LangJavaScript ||
		lang == LangTypeScript || lang == LangCSharp || lang == LangDart ||
		lang == LangRust || lang == LangPHP

	if usesCBlock {
		if inBlock {
			// We are inside a /* … */ block — look for the closing */.
			if idx := strings.Index(line, "*/"); idx >= 0 {
				// Rest of the line after */ may contain code.
				line = line[idx+2:]
				inBlock = false
			} else {
				// Entire line is inside a block comment.
				return "", true
			}
		}

		// Scan through the remaining text handling /* and // in order.
		result := strings.Builder{}
		i := 0
		for i < len(line) {
			if i+1 < len(line) && line[i] == '/' && line[i+1] == '*' {
				// Block comment opens — find closing */ on this line.
				if end := strings.Index(line[i+2:], "*/"); end >= 0 {
					// Block comment closes on the same line — skip it and continue.
					i = i + 2 + end + 2
					continue
				}
				// Block comment continues past this line.
				inBlock = true
				break
			}
			if i+1 < len(line) && line[i] == '/' && line[i+1] == '/' {
				// Line comment — everything from here is a comment.
				break
			}
			// Skip content inside string literals so // inside a string isn't
			// treated as a comment. We handle single-quote and double-quote strings.
			if line[i] == '"' || line[i] == '\'' {
				quote := line[i]
				result.WriteByte(line[i])
				i++
				for i < len(line) {
					result.WriteByte(line[i])
					if line[i] == '\\' && i+1 < len(line) {
						// Escaped character — skip next byte.
						i++
						result.WriteByte(line[i])
					} else if line[i] == quote {
						break
					}
					i++
				}
				i++
				continue
			}
			result.WriteByte(line[i])
			i++
		}
		return result.String(), inBlock
	}

	// ── Hash-style line comments  (#) ────────────────────────────────────────
	// Python and Ruby use # for line comments; no multi-line /* */ syntax.
	if lang == LangPython || lang == LangRuby {
		// Walk through the line respecting string literals so that a # inside
		// a string (e.g. 'color: #fff') is not mistaken for a comment.
		i := 0
		result := strings.Builder{}
		for i < len(line) {
			ch := line[i]
			if ch == '#' {
				// Rest of line is a comment.
				break
			}
			if ch == '"' || ch == '\'' {
				quote := ch
				result.WriteByte(ch)
				i++
				for i < len(line) {
					result.WriteByte(line[i])
					if line[i] == '\\' && i+1 < len(line) {
						i++
						result.WriteByte(line[i])
					} else if line[i] == quote {
						break
					}
					i++
				}
				i++
				continue
			}
			result.WriteByte(ch)
			i++
		}
		return result.String(), false
	}

	// For any other language just return the line unchanged.
	return line, inBlock
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
	case ".dart":
		return LangDart
	case ".js", ".jsx", ".mjs", ".cjs":
		return LangJavaScript
	case ".ts", ".tsx":
		return LangTypeScript
	case ".cs":
		return LangCSharp
	case ".php":
		return LangPHP
	case ".rb":
		return LangRuby
	case ".rs":
		return LangRust
	default:
		return ""
	}
}

