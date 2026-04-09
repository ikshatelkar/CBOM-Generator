package vex

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cbom-scanner/pkg/model"
	"github.com/cbom-scanner/pkg/output"
)

// Evaluate is the VEX evaluation pipeline step.
//
// It receives the enriched crypto nodes and the vulnerability findings produced
// by the existing analyzer, then evaluates each finding through the VEXRuleRegistry.
//
// Returns a map of bom-ref → output.VEXBlock ready to be attached to components
// via Generator.AnnotateVEX. Only components that have at least one finding get
// an entry; the map is empty if nothing was flagged.
func Evaluate(
	nodes []model.INode,
	findings map[string][]output.ComponentVuln,
	registry *VEXRuleRegistry,
) map[string]output.VEXBlock {

	// Build a fast lookup: bom-ref → node, so we can extract ComponentInfo.
	nodeByRef := make(map[string]model.INode, len(nodes))
	for _, node := range nodes {
		ref := bomRefForNode(node)
		if ref != "" {
			nodeByRef[ref] = node
		}
	}

	result := make(map[string]output.VEXBlock)

	for ref, vulns := range findings {
		node, ok := nodeByRef[ref]
		if !ok {
			continue
		}
		info := componentInfoFromNode(node)

		var entries []output.VEXEntry
		for _, vuln := range vulns {
			vr := registry.EvaluateAll(vuln.ID, info)
			entries = append(entries, output.VEXEntry{
				CVEID:           vr.CVEID,
				VEXStatus:       string(vr.Status),
				Justification:   string(vr.Justification),
				ImpactStatement: vr.ImpactStatement,
				Confidence:      string(vr.Confidence),
			})
		}

		if len(entries) > 0 {
			result[ref] = output.VEXBlock{Vulnerabilities: entries}
		}
	}

	return result
}

// componentInfoFromNode extracts the crypto properties needed for VEX rule evaluation.
func componentInfoFromNode(node model.INode) ComponentInfo {
	info := ComponentInfo{}

	switch n := node.(type) {

	case *model.Algorithm:
		info.Algorithm = n.Name
		info.Primitive = string(n.PrimitiveType)
		if modeNode, has := n.HasChildOfKind(model.KindMode); has {
			info.Mode = modeNode.AsString()
		}
		if padNode, has := n.HasChildOfKind(model.KindPadding); has {
			info.Padding = padNode.AsString()
		}
		if klNode, has := n.HasChildOfKind(model.KindKeyLength); has {
			if ip, ok := klNode.(*model.IntProperty); ok {
				info.KeySize = ip.Value
			}
		}

	case *model.Key:
		info.Algorithm = n.Name
		if klNode, has := n.HasChildOfKind(model.KindKeyLength); has {
			if ip, ok := klNode.(*model.IntProperty); ok {
				info.KeySize = ip.Value
			}
		}
		// Infer primitive from key name for crypto-specific rules
		name := strings.ToUpper(n.Name)
		switch {
		case name == "RSA":
			info.Primitive = "pke"
		case strings.Contains(name, "EC") || strings.Contains(name, "ECDSA"):
			info.Primitive = "signature"
		case name == "AES" || name == "DES" || name == "3DES":
			info.Primitive = "block-cipher"
		}

	case *model.Protocol:
		info.Algorithm = n.Name
		if vNode, has := n.HasChildOfKind(model.KindVersion); has {
			info.Version = vNode.AsString()
		}

	case *model.CipherSuite:
		info.Algorithm = n.Name
	}

	return info
}

// bomRefForNode computes the bom-ref for a node using the same formula as
// pkg/output/cyclonedx.go and pkg/analyzer/analyzer.go.
func bomRefForNode(node model.INode) string {
	switch n := node.(type) {
	case *model.Algorithm:
		return fmt.Sprintf("crypto-algorithm-%s-%s-%d",
			n.Name, filepath.Base(n.DetectionLocation.FilePath), n.DetectionLocation.Line)
	case *model.Key:
		return fmt.Sprintf("crypto-key-%s-%s-%d",
			n.Name, filepath.Base(n.DetectionLocation.FilePath), n.DetectionLocation.Line)
	case *model.Protocol:
		return fmt.Sprintf("crypto-protocol-%s-%s-%d",
			n.Name, filepath.Base(n.DetectionLocation.FilePath), n.DetectionLocation.Line)
	case *model.CipherSuite:
		return fmt.Sprintf("crypto-ciphersuite-%s-%s-%d",
			n.Name, filepath.Base(n.DetectionLocation.FilePath), n.DetectionLocation.Line)
	}
	return ""
}
