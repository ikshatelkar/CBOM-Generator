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
	// Default scanner buffer is 64 KB — too small for minified JS or generated
	// source files with long lines. Increase to 1 MB to avoid silently dropping lines.
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)
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
				FilePath:    filePath,
				Line:        lineNum,
				Column:      strings.Index(line, matches[0]) + 1,
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

