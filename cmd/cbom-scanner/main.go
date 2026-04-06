package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/enricher"
	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/output"
	"github.com/cbom-scanner/pkg/rules/java"
	"github.com/cbom-scanner/pkg/rules/python"
)

const version = "0.1.0"

func main() {
	var (
		targetDir  string
		outputFile string
		format     string
		showVer    bool
		verbose    bool
	)

	flag.StringVar(&targetDir, "dir", ".", "Directory to scan for cryptographic assets")
	flag.StringVar(&outputFile, "output", "cbom.json", "Output file path for the CBOM")
	flag.StringVar(&format, "format", "json", "Output format (json)")
	flag.BoolVar(&showVer, "version", false, "Print version and exit")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.Parse()

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

	// 5. Generate CBOM output
	gen := output.NewGenerator(absDir)
	gen.AddNodes(allNodes)

	if err := gen.WriteJSON(outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CBOM: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CBOM written to: %s\n", outputFile)

	// 6. Print summary
	printSummary(allNodes)
}

func printSummary(nodes []model.INode) {
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

	fmt.Println("\n--- Summary ---")
	fmt.Printf("  Algorithms:    %d\n", algos)
	fmt.Printf("  Keys:          %d\n", keys)
	fmt.Printf("  Protocols:     %d\n", protocols)
	fmt.Printf("  Cipher Suites: %d\n", suites)
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
