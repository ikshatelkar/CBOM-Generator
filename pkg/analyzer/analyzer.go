package analyzer

import (
	"fmt"
	"path/filepath"

	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/output"
	"github.com/cbom-scanner/pkg/vulndb"
)

// Analyze walks every detected node, evaluates each against the VulnRuleRegistry,
// and returns a map of bom-ref -> []ComponentVuln.
//
// Each entry can be passed directly to Generator.AnnotateVulnerabilities so that
// the findings are embedded inside the matching component rather than in a separate list.
func Analyze(nodes []model.INode, registry *vulndb.VulnRuleRegistry) map[string][]output.ComponentVuln {
	seen := make(map[string]bool)
	findings := make(map[string][]output.ComponentVuln)

	for _, node := range nodes {
		bomRef := BomRefForNode(node)
		if bomRef == "" {
			continue
		}

		for _, rule := range registry.Evaluate(node) {
			key := rule.ID + "|" + bomRef
			if seen[key] {
				continue
			}
			seen[key] = true

			findings[bomRef] = append(findings[bomRef], output.ComponentVuln{
				ID:       rule.ID,
				Severity: rule.Severity,
			})
		}
	}

	return findings
}

// BomRefForNode computes the bom-ref string for a node using the same formula
// as pkg/output/cyclonedx.go so that findings match the generated component refs.
func BomRefForNode(node model.INode) string {
	switch n := node.(type) {
	case *model.Algorithm:
		return fmt.Sprintf("crypto-algorithm-%s-%s-%d",
			n.Name,
			filepath.Base(n.DetectionLocation.FilePath),
			n.DetectionLocation.Line)
	case *model.Key:
		return fmt.Sprintf("crypto-key-%s-%s-%d",
			n.Name,
			filepath.Base(n.DetectionLocation.FilePath),
			n.DetectionLocation.Line)
	case *model.Protocol:
		return fmt.Sprintf("crypto-protocol-%s-%s-%d",
			n.Name,
			filepath.Base(n.DetectionLocation.FilePath),
			n.DetectionLocation.Line)
	case *model.CipherSuite:
		return fmt.Sprintf("crypto-ciphersuite-%s-%s-%d",
			n.Name,
			filepath.Base(n.DetectionLocation.FilePath),
			n.DetectionLocation.Line)
	}
	return ""
}
