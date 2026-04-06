package output

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cbom-scanner/pkg/model"
)

// CycloneDX CBOM output structures (CycloneDX 1.6 compliant).

type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []ToolInfo `json:"tools"`
}

type ToolInfo struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type             string            `json:"type"`
	BOMRef           string            `json:"bom-ref"`
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	Description      string            `json:"description,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
	Properties       []Property        `json:"properties,omitempty"`
}

type CryptoProperties struct {
	AssetType                       string                           `json:"assetType"`
	AlgorithmProperties             *AlgorithmProperties             `json:"algorithmProperties,omitempty"`
	ProtocolProperties              *ProtocolProperties              `json:"protocolProperties,omitempty"`
	RelatedCryptoMaterialProperties *RelatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty"`
	OID                             string                           `json:"oid,omitempty"`
}

type AlgorithmProperties struct {
	Primitive              string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	Curve                  string   `json:"curve,omitempty"`
	ExecutionEnvironment   string   `json:"executionEnvironment,omitempty"`
	ImplementationPlatform string   `json:"implementationPlatform,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	Padding                string   `json:"padding,omitempty"`
}

type ProtocolProperties struct {
	Type         string        `json:"type,omitempty"`
	Version      string        `json:"version,omitempty"`
	CipherSuites []CipherSuite `json:"cipherSuites,omitempty"`
}

type CipherSuite struct {
	Name       string   `json:"name"`
	Algorithms []string `json:"algorithms,omitempty"`
}

type RelatedCryptoMaterialProperties struct {
	Type string `json:"type,omitempty"`
	Size int    `json:"size,omitempty"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

type Occurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// Generator builds CBOM from detected and enriched nodes.
type Generator struct {
	projectDir string
	components map[string]*Component
	deps       map[string][]string
}

func NewGenerator(projectDir string) *Generator {
	return &Generator{
		projectDir: projectDir,
		components: make(map[string]*Component),
		deps:       make(map[string][]string),
	}
}

// AddNodes adds a list of detected nodes to the CBOM.
func (g *Generator) AddNodes(nodes []model.INode) {
	for _, node := range nodes {
		g.addNode(node, "")
	}
}

func (g *Generator) addNode(node model.INode, parentRef string) string {
	switch n := node.(type) {
	case *model.Algorithm:
		return g.addAlgorithm(n, parentRef)
	case *model.Key:
		return g.addKey(n, parentRef)
	case *model.Protocol:
		return g.addProtocol(n, parentRef)
	case *model.CipherSuite:
		return g.addCipherSuiteAsComponent(n, parentRef)
	}
	return ""
}

func (g *Generator) addAlgorithm(algo *model.Algorithm, parentRef string) string {
	ref := fmt.Sprintf("crypto-algorithm-%s-%s-%d", algo.Name, filepath.Base(algo.DetectionLocation.FilePath), algo.DetectionLocation.Line)

	if _, exists := g.components[ref]; exists {
		g.linkDep(parentRef, ref)
		return ref
	}

	var funcs []string
	for _, f := range algo.Functions {
		funcs = append(funcs, string(f))
	}

	algProps := &AlgorithmProperties{
		Primitive:       string(algo.PrimitiveType),
		CryptoFunctions: funcs,
	}

	if modeNode, ok := algo.HasChildOfKind(model.KindMode); ok {
		algProps.Mode = modeNode.AsString()
	}
	if padNode, ok := algo.HasChildOfKind(model.KindPadding); ok {
		algProps.Padding = padNode.AsString()
	}
	if curveNode, ok := algo.HasChildOfKind(model.KindCurve); ok {
		algProps.Curve = curveNode.AsString()
	}

	cp := &CryptoProperties{
		AssetType:           "algorithm",
		AlgorithmProperties: algProps,
	}
	if oidNode, ok := algo.HasChildOfKind(model.KindOid); ok {
		cp.OID = oidNode.AsString()
	}

	var props []Property
	if kl, ok := algo.HasChildOfKind(model.KindKeyLength); ok {
		props = append(props, Property{Name: "keyLength", Value: kl.AsString()})
	}
	if bs, ok := algo.HasChildOfKind(model.KindBlockSize); ok {
		props = append(props, Property{Name: "blockSize", Value: bs.AsString()})
	}
	if ds, ok := algo.HasChildOfKind(model.KindDigestSize); ok {
		props = append(props, Property{Name: "digestSize", Value: ds.AsString()})
	}
	if tl, ok := algo.HasChildOfKind(model.KindTagLength); ok {
		props = append(props, Property{Name: "tagLength", Value: tl.AsString()})
	}

	props = append(props, Property{Name: "bundle", Value: algo.DetectionLocation.Bundle})

	comp := &Component{
		Type:             "crypto-asset",
		BOMRef:           ref,
		Name:             algo.Name,
		CryptoProperties: cp,
		Evidence:         g.makeEvidence(algo.DetectionLocation),
		Properties:       props,
	}

	g.components[ref] = comp
	g.linkDep(parentRef, ref)
	return ref
}

func (g *Generator) addKey(key *model.Key, parentRef string) string {
	keyType := "unknown"
	switch key.KeyKind {
	case model.KindSecretKey:
		keyType = "secret-key"
	case model.KindPublicKey:
		keyType = "public-key"
	case model.KindPrivateKey:
		keyType = "private-key"
	default:
		keyType = "key"
	}

	ref := fmt.Sprintf("crypto-key-%s-%s-%d", key.Name, filepath.Base(key.DetectionLocation.FilePath), key.DetectionLocation.Line)

	if _, exists := g.components[ref]; exists {
		g.linkDep(parentRef, ref)
		return ref
	}

	size := 0
	if kl, ok := key.HasChildOfKind(model.KindKeyLength); ok {
		if ip, ok := kl.(*model.IntProperty); ok {
			size = ip.Value
		}
	}

	cp := &CryptoProperties{
		AssetType: "related-crypto-material",
		RelatedCryptoMaterialProperties: &RelatedCryptoMaterialProperties{
			Type: keyType,
			Size: size,
		},
	}

	comp := &Component{
		Type:             "crypto-asset",
		BOMRef:           ref,
		Name:             key.Name,
		CryptoProperties: cp,
		Evidence:         g.makeEvidence(key.DetectionLocation),
		Properties: []Property{
			{Name: "bundle", Value: key.DetectionLocation.Bundle},
		},
	}

	g.components[ref] = comp
	g.linkDep(parentRef, ref)

	// Add child algorithm as dependency
	for _, child := range key.Children() {
		g.addNode(child, ref)
	}

	return ref
}

func (g *Generator) addProtocol(proto *model.Protocol, parentRef string) string {
	ref := fmt.Sprintf("crypto-protocol-%s-%s-%d", proto.Name, filepath.Base(proto.DetectionLocation.FilePath), proto.DetectionLocation.Line)

	if _, exists := g.components[ref]; exists {
		g.linkDep(parentRef, ref)
		return ref
	}

	ver := ""
	if vNode, ok := proto.HasChildOfKind(model.KindVersion); ok {
		ver = vNode.AsString()
	}

	cp := &CryptoProperties{
		AssetType: "protocol",
		ProtocolProperties: &ProtocolProperties{
			Type:    proto.Name,
			Version: ver,
		},
	}

	comp := &Component{
		Type:             "crypto-asset",
		BOMRef:           ref,
		Name:             proto.Name,
		CryptoProperties: cp,
		Evidence:         g.makeEvidence(proto.DetectionLocation),
		Properties: []Property{
			{Name: "bundle", Value: proto.DetectionLocation.Bundle},
		},
	}

	g.components[ref] = comp
	g.linkDep(parentRef, ref)
	return ref
}

func (g *Generator) addCipherSuiteAsComponent(cs *model.CipherSuite, parentRef string) string {
	ref := fmt.Sprintf("crypto-ciphersuite-%s-%s-%d", cs.Name, filepath.Base(cs.DetectionLocation.FilePath), cs.DetectionLocation.Line)

	if _, exists := g.components[ref]; exists {
		g.linkDep(parentRef, ref)
		return ref
	}

	cp := &CryptoProperties{
		AssetType: "protocol",
		ProtocolProperties: &ProtocolProperties{
			CipherSuites: []CipherSuite{{Name: cs.Name}},
		},
	}

	comp := &Component{
		Type:             "crypto-asset",
		BOMRef:           ref,
		Name:             cs.Name,
		CryptoProperties: cp,
		Evidence:         g.makeEvidence(cs.DetectionLocation),
	}

	g.components[ref] = comp
	g.linkDep(parentRef, ref)
	return ref
}

func (g *Generator) linkDep(parentRef, childRef string) {
	if parentRef == "" || childRef == "" {
		return
	}
	for _, existing := range g.deps[parentRef] {
		if existing == childRef {
			return
		}
	}
	g.deps[parentRef] = append(g.deps[parentRef], childRef)
}

func (g *Generator) makeEvidence(loc model.DetectionLocation) *Evidence {
	relPath := loc.FilePath
	if g.projectDir != "" {
		if rel, err := filepath.Rel(g.projectDir, loc.FilePath); err == nil {
			relPath = filepath.ToSlash(rel)
		}
	}
	return &Evidence{
		Occurrences: []Occurrence{
			{Location: relPath, Line: loc.Line, Column: loc.Column},
		},
	}
}

// Generate produces the final CycloneDX BOM.
func (g *Generator) Generate() *BOM {
	var components []Component
	for _, c := range g.components {
		components = append(components, *c)
	}

	var deps []Dependency
	for ref, children := range g.deps {
		deps = append(deps, Dependency{Ref: ref, DependsOn: children})
	}

	return &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + generateUUID(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []ToolInfo{
				{
					Vendor:  "cbom-scanner",
					Name:    "cbom-scanner",
					Version: "0.1.0",
				},
			},
		},
		Components:   components,
		Dependencies: deps,
	}
}

// WriteJSON writes BOM to a JSON file.
func (g *Generator) WriteJSON(outputPath string) error {
	bom := g.Generate()
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal BOM: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write BOM file: %w", err)
	}
	return nil
}

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}
