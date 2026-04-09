package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cbom-scanner/pkg/analyzer"
	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/enricher"
	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/output"
	"github.com/cbom-scanner/pkg/rules/java"
	"github.com/cbom-scanner/pkg/rules/python"
	"github.com/cbom-scanner/pkg/vex"
	"github.com/cbom-scanner/pkg/vulndb"
)

const version = "0.1.0"

// severityOrder defines the numeric weight of each severity level.
// Higher number = more severe. Used to evaluate the --fail-on threshold.
var severityOrder = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

func main() {
	var (
		targetDir   string
		outputFile  string
		sarifFile   string
		format      string
		failOn      string
		minSeverity string
		workers     int
		showVer     bool
		verbose     bool
	)

	flag.StringVar(&targetDir, "dir", ".", "Directory to scan for cryptographic assets")
	flag.StringVar(&outputFile, "output", "cbom.json", "Output file path for the CBOM")
	flag.StringVar(&sarifFile, "sarif", "", "Also write a SARIF 2.1.0 report to this file path (e.g. results.sarif)")
	flag.StringVar(&format, "format", "json", "Output format (json)")
	flag.StringVar(&failOn, "fail-on", "", "Exit with code 1 if any vulnerability at or above this severity is found (critical|high|medium|low|info)")
	flag.StringVar(&minSeverity, "min-severity", "", "Only include vulnerabilities at or above this severity in the CBOM and SARIF output (critical|high|medium|low|info)")
	flag.IntVar(&workers, "workers", 0, "Number of parallel file-scanning goroutines (default: number of CPU cores)")
	flag.BoolVar(&showVer, "version", false, "Print version and exit")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.Parse()

	// Validate --fail-on value if provided
	if failOn != "" {
		if _, ok := severityOrder[failOn]; !ok {
			fmt.Fprintf(os.Stderr, "Error: invalid --fail-on value %q. Must be one of: critical, high, medium, low, info\n", failOn)
			os.Exit(1)
		}
	}

	// Validate --min-severity value if provided
	if minSeverity != "" {
		if _, ok := severityOrder[minSeverity]; !ok {
			fmt.Fprintf(os.Stderr, "Error: invalid --min-severity value %q. Must be one of: critical, high, medium, low, info\n", minSeverity)
			os.Exit(1)
		}
	}

	if showVer {
		fmt.Printf("cbom-scanner v%s\n", version)
		os.Exit(0)
	}

	// Resolve target directory
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving directory: %v\n", err)
		os.Exit(1)
	}

	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: %q is not a valid directory\n", absDir)
		os.Exit(1)
	}

	fmt.Printf("cbom-scanner v%s\n", version)
	fmt.Printf("Scanning: %s\n", absDir)

	// 1. Build rule registry
	registry := detection.NewRuleRegistry()
	java.RegisterJCADetectionRules(registry)
	java.RegisterBouncyCastleDetectionRules(registry)
	python.RegisterPycaDetectionRules(registry)

	ruleCount := len(registry.AllRules())
	fmt.Printf("Loaded %d detection rules\n", ruleCount)

	// 2. Run detection engine
	engine := detection.NewEngine(registry)
	engine.Workers = workers
	result := engine.ScanDirectory(absDir)

	if verbose {
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", e)
		}
	}

	// 3. Collect all detected nodes
	var allNodes []model.INode
	for _, finding := range result.Findings {
		allNodes = append(allNodes, finding.Nodes...)
	}

	fmt.Printf("Detected %d cryptographic assets in %d findings\n", len(allNodes), len(result.Findings))

	if len(allNodes) == 0 {
		fmt.Println("No cryptographic assets found.")
		writeEmptyBOM(outputFile, absDir)
		return
	}

	// 4. Enrich detected nodes
	allNodes = enricher.Enrich(allNodes)

	// 5. Build vulnerability rule registry and analyse enriched nodes
	vulnRegistry := vulndb.NewVulnRuleRegistry()
	vulndb.RegisterAllRules(vulnRegistry)

	fmt.Printf("Loaded %d vulnerability rules\n", len(vulnRegistry.AllRules()))

	vulns := analyzer.Analyze(allNodes, vulnRegistry)

	// 5b. Apply --min-severity filter — drop findings below the threshold so
	// they are excluded from the CBOM, SARIF, VEX assessment, and summary.
	if minSeverity != "" {
		vulns = filterVulnsBySeverity(vulns, minSeverity)
		fmt.Printf("Filtering: showing only %s+ severity findings\n", minSeverity)
	}

	// 6. VEX evaluation layer (additive — does not modify existing fields)
	vexRegistry := vex.NewVEXRuleRegistry()
	vex.RegisterAllVEXRules(vexRegistry)

	fmt.Printf("Loaded %d VEX rules\n", len(vexRegistry.AllRules()))

	vexFindings := vex.Evaluate(allNodes, vulns, vexRegistry)

	// 7. Generate CBOM output
	gen := output.NewGenerator(absDir)
	gen.AddNodes(allNodes)
	gen.AnnotateVulnerabilities(vulns)
	gen.AnnotateVEX(vexFindings)

	if err := gen.WriteJSON(outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CBOM: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CBOM written to: %s\n", outputFile)

	// 8b. Optional SARIF output
	if sarifFile != "" {
		sarifMeta := make(map[string]output.SARIFRuleMeta)
		for _, rule := range vulnRegistry.AllRules() {
			sarifMeta[rule.ID] = output.SARIFRuleMeta{
				Title:          rule.Title,
				Description:    rule.Description,
				Recommendation: rule.Recommendation,
				Severity:       rule.Severity,
				References:     rule.References,
			}
		}
		if err := gen.WriteSARIF(sarifFile, sarifMeta); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing SARIF: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("SARIF report written to: %s\n", sarifFile)
	}

	// 8. Print asset report table
	gen.PrintReport(os.Stdout)

	// 8b. Print summary
	printSummary(allNodes, vulns, vexFindings)

	// 9. Fail-on threshold check
	if failOn != "" {
		threshold := severityOrder[failOn]
		for _, vulnList := range vulns {
			for _, v := range vulnList {
				if severityOrder[v.Severity] >= threshold {
					fmt.Fprintf(os.Stderr, "\nFAILED: vulnerability at or above %q severity detected (found %q). Exit code 1.\n", failOn, v.Severity)
					os.Exit(1)
				}
			}
		}
	}
}

func printSummary(nodes []model.INode, findings map[string][]output.ComponentVuln, vexFindings map[string]output.VEXBlock) {
	algos := 0
	keys := 0
	protocols := 0
	suites := 0

	for _, n := range nodes {
		switch n.Kind() {
		case model.KindAlgorithm:
			algos++
		case model.KindSecretKey, model.KindPublicKey, model.KindPrivateKey, model.KindKey:
			keys++
		case model.KindProtocol:
			protocols++
		case model.KindCipherSuite:
			suites++
		}
	}

	// Count vulnerabilities by severity across all components
	sevCount := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	total := 0
	for _, vulns := range findings {
		for _, v := range vulns {
			sevCount[v.Severity]++
			total++
		}
	}

	fmt.Println("\n--- Summary ---")
	fmt.Printf("  Algorithms:    %d\n", algos)
	fmt.Printf("  Keys:          %d\n", keys)
	fmt.Printf("  Protocols:     %d\n", protocols)
	fmt.Printf("  Cipher Suites: %d\n", suites)
	fmt.Println("\n--- Vulnerabilities ---")
	fmt.Printf("  Total:    %d\n", total)
	fmt.Printf("  Critical: %d\n", sevCount["critical"])
	fmt.Printf("  High:     %d\n", sevCount["high"])
	fmt.Printf("  Medium:   %d\n", sevCount["medium"])
	fmt.Printf("  Low:      %d\n", sevCount["low"])
	fmt.Printf("  Info:     %d\n", sevCount["info"])

	// VEX status breakdown
	vexCount := map[string]int{
		"affected":             0,
		"not_affected":         0,
		"fixed":                0,
		"under_investigation":  0,
	}
	for _, block := range vexFindings {
		for _, entry := range block.Vulnerabilities {
			vexCount[entry.VEXStatus]++
		}
	}
	fmt.Println("\n--- VEX Assessment ---")
	fmt.Printf("  Affected:             %d\n", vexCount["affected"])
	fmt.Printf("  Not Affected:         %d\n", vexCount["not_affected"])
	fmt.Printf("  Fixed:                %d\n", vexCount["fixed"])
	fmt.Printf("  Under Investigation:  %d\n", vexCount["under_investigation"])
}

func writeEmptyBOM(outputFile, projectDir string) {
	gen := output.NewGenerator(projectDir)
	if err := gen.WriteJSON(outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing empty CBOM: %v\n", err)
		os.Exit(1)
	}

	bom := gen.Generate()
	data, _ := json.MarshalIndent(bom, "", "  ")
	_ = os.WriteFile(outputFile, data, 0644)
	fmt.Printf("Empty CBOM written to: %s\n", outputFile)
}

// filterVulnsBySeverity returns a new map containing only the vulnerabilities
// whose severity is at or above the given threshold.
// Components whose entire vuln list is filtered out are dropped from the map.
func filterVulnsBySeverity(vulns map[string][]output.ComponentVuln, minSev string) map[string][]output.ComponentVuln {
	threshold := severityOrder[minSev]
	filtered := make(map[string][]output.ComponentVuln)
	for ref, list := range vulns {
		var kept []output.ComponentVuln
		for _, v := range list {
			if severityOrder[v.Severity] >= threshold {
				kept = append(kept, v)
			}
		}
		if len(kept) > 0 {
			filtered[ref] = kept
		}
	}
	return filtered
}
