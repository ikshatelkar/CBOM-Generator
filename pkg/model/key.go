package model

// Key represents a detected cryptographic key asset.
type Key struct {
	BaseNode
	Name              string            `json:"name"`
	KeyKind           NodeKind          `json:"keyKind"` // KindSecretKey, KindPublicKey, KindPrivateKey, or KindKey
	DetectionLocation DetectionLocation `json:"detectionLocation"`
}

func NewKey(name string, keyKind NodeKind, loc DetectionLocation) *Key {
	return &Key{
		BaseNode:          NewBaseNode(),
		Name:              name,
		KeyKind:           keyKind,
		DetectionLocation: loc,
	}
}

func (k *Key) Kind() NodeKind   { return k.KeyKind }
func (k *Key) AsString() string { return k.Name }

// Protocol represents a detected cryptographic protocol (TLS, SSL, etc.).
type Protocol struct {
	BaseNode
	Name              string            `json:"name"`
	DetectionLocation DetectionLocation `json:"detectionLocation"`
}

func NewProtocol(name string, loc DetectionLocation) *Protocol {
	return &Protocol{
		BaseNode:          NewBaseNode(),
		Name:              name,
		DetectionLocation: loc,
	}
}

func (p *Protocol) Kind() NodeKind   { return KindProtocol }
func (p *Protocol) AsString() string { return p.Name }

// CipherSuite represents a named cipher suite (e.g. TLS_AES_256_GCM_SHA384).
type CipherSuite struct {
	BaseNode
	Name              string            `json:"name"`
	DetectionLocation DetectionLocation `json:"detectionLocation"`
}

func NewCipherSuite(name string, loc DetectionLocation) *CipherSuite {
	return &CipherSuite{
		BaseNode:          NewBaseNode(),
		Name:              name,
		DetectionLocation: loc,
	}
}

func (c *CipherSuite) Kind() NodeKind   { return KindCipherSuite }
func (c *CipherSuite) AsString() string { return c.Name }
