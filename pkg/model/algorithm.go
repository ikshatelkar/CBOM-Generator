package model

// Algorithm represents a detected cryptographic algorithm.
type Algorithm struct {
	BaseNode
	Name              string            `json:"name"`
	PrimitiveType     Primitive         `json:"primitive"`
	DetectionLocation DetectionLocation `json:"detectionLocation"`
	Functions         []CryptoFunc      `json:"functions,omitempty"`
}

func NewAlgorithm(name string, prim Primitive, loc DetectionLocation) *Algorithm {
	return &Algorithm{
		BaseNode:          NewBaseNode(),
		Name:              name,
		PrimitiveType:     prim,
		DetectionLocation: loc,
	}
}

func (a *Algorithm) Kind() NodeKind   { return KindAlgorithm }
func (a *Algorithm) AsString() string { return a.Name }

func (a *Algorithm) AddFunction(f CryptoFunc) {
	for _, existing := range a.Functions {
		if existing == f {
			return
		}
	}
	a.Functions = append(a.Functions, f)
}
