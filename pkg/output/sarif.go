package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SARIFRuleMeta carries the descriptive metadata for one vulnerability rule.
// It is constructed in main.go from the vulndb registry so that this package
// stays decoupled from pkg/vulndb.
type SARIFRuleMeta struct {
	Title          string
	Description    string
	Recommendation string
	Severity       string   // "critical" | "high" | "medium" | "low" | "info"
	References     []string // NIST SP, RFC, CVE, etc.
}

// --------------------------------------------------------------------------
// SARIF 2.1.0 structures (OASIS standard)
// --------------------------------------------------------------------------

type sarifReport struct {
	Schema  string    `json:"$schema"`
	Version string    `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifMessage      `json:"shortDescription"`
	FullDescription      sarifMessage      `json:"fullDescription"`
	DefaultConfiguration sarifRuleConfig   `json:"defaultConfiguration"`
	Help                 sarifMessage      `json:"help"`
	Properties           sarifRuleProps    `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"` // "error" | "warning" | "note"
}

type sarifRuleProps struct {
	Tags     []string `json:"tags"`
	Severity string   `json:"severity"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// --------------------------------------------------------------------------
// Severity helpers
// --------------------------------------------------------------------------

// sarifLevel maps our severity strings to the three SARIF levels.
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default: // low, info
		return "note"
	}
}

// ruleNameFromID converts "CBOM-HASH-001" → "CbomHash001" (PascalCase identifier
// required by the SARIF spec's "name" property).
func ruleNameFromID(id string) string {
	parts := strings.Split(id, "-")
	var sb strings.Builder
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		sb.WriteString(strings.ToUpper(p[:1]) + strings.ToLower(p[1:]))
	}
	return sb.String()
}

// --------------------------------------------------------------------------
// Generator methods
// --------------------------------------------------------------------------

// GenerateSARIF builds a SARIF 2.1.0 report from all vulnerability annotations
// currently embedded in the generator's components.
//
// ruleMeta maps rule IDs (e.g. "CBOM-HASH-001") to their descriptive metadata.
// Any rule ID found in a component that has no entry in ruleMeta is still emitted
// — it just gets minimal placeholder text.
func (g *Generator) GenerateSARIF(ruleMeta map[string]SARIFRuleMeta) *sarifReport {
	// Collect the set of rule IDs that actually fired so we only emit those.
	usedRuleIDs := make(map[string]struct{})
	type resultEntry struct {
		ruleID   string
		severity string
		uri      string
		line     int
		column   int
		name     string
	}
	var resultEntries []resultEntry

	for _, comp := range g.components {
		for _, v := range comp.Vulnerabilities {
			usedRuleIDs[v.ID] = struct{}{}

			loc := sarifArtifactLocation{URIBaseID: "%SRCROOT%"}
			line := 0
			col := 0
			compName := comp.Name

			if comp.Evidence != nil && len(comp.Evidence.Occurrences) > 0 {
				occ := comp.Evidence.Occurrences[0]
				loc.URI = occ.Location
				line = occ.Line
				col = occ.Column
			}

			resultEntries = append(resultEntries, resultEntry{
				ruleID:   v.ID,
				severity: v.Severity,
				uri:      loc.URI,
				line:     line,
				column:   col,
				name:     compName,
			})

			_ = loc
		}
	}

	// Build the rules list (only fired rules).
	var rules []sarifRule
	for id := range usedRuleIDs {
		meta, ok := ruleMeta[id]
		if !ok {
			meta = SARIFRuleMeta{
				Title:       id,
				Description: id,
				Severity:    "info",
			}
		}

		helpText := meta.Recommendation
		if helpText == "" {
			helpText = meta.Description
		}
		if len(meta.References) > 0 {
			helpText += "\n\nReferences: " + strings.Join(meta.References, ", ")
		}

		rules = append(rules, sarifRule{
			ID:               id,
			Name:             ruleNameFromID(id),
			ShortDescription: sarifMessage{Text: meta.Title},
			FullDescription:  sarifMessage{Text: meta.Description},
			DefaultConfiguration: sarifRuleConfig{
				Level: sarifLevel(meta.Severity),
			},
			Help: sarifMessage{Text: helpText},
			Properties: sarifRuleProps{
				Tags:     []string{"cryptography", "cbom"},
				Severity: meta.Severity,
			},
		})
	}

	// Build results.
	var results []sarifResult
	for _, e := range resultEntries {
		meta, ok := ruleMeta[e.ruleID]
		title := e.ruleID
		if ok {
			title = meta.Title
		}

		msgText := fmt.Sprintf("%s: %q detected", title, e.name)
		if e.uri != "" {
			msgText = fmt.Sprintf("%s: %q detected in %s", title, e.name, e.uri)
		}

		startLine := e.line
		if startLine == 0 {
			startLine = 1
		}

		result := sarifResult{
			RuleID:  e.ruleID,
			Level:   sarifLevel(e.severity),
			Message: sarifMessage{Text: msgText},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI:       e.uri,
							URIBaseID: "%SRCROOT%",
						},
						Region: sarifRegion{
							StartLine:   startLine,
							StartColumn: e.column,
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	return &sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "cbom-scanner",
						Version:        "0.1.0",
						InformationURI: "https://github.com/cbom-scanner/cbom-scanner",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// WriteSARIF writes a SARIF 2.1.0 report to the given file path.
func (g *Generator) WriteSARIF(outputPath string, ruleMeta map[string]SARIFRuleMeta) error {
	report := g.GenerateSARIF(ruleMeta)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal SARIF: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write SARIF file: %w", err)
	}
	return nil
}
