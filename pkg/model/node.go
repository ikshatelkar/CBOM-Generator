package model

// NodeKind identifies the type of a crypto node (Algorithm, Key, Protocol, etc.)
type NodeKind string

const (
	KindAlgorithm     NodeKind = "Algorithm"
	KindKey           NodeKind = "Key"
	KindSecretKey     NodeKind = "SecretKey"
	KindPublicKey     NodeKind = "PublicKey"
	KindPrivateKey    NodeKind = "PrivateKey"
	KindProtocol      NodeKind = "Protocol"
	KindCipherSuite   NodeKind = "CipherSuite"
	KindKeyLength     NodeKind = "KeyLength"
	KindBlockSize     NodeKind = "BlockSize"
	KindDigestSize    NodeKind = "DigestSize"
	KindTagLength     NodeKind = "TagLength"
	KindNonceLength   NodeKind = "NonceLength"
	KindSaltLength    NodeKind = "SaltLength"
	KindIVLength      NodeKind = "IVLength"
	KindMode          NodeKind = "Mode"
	KindPadding       NodeKind = "Padding"
	KindOid           NodeKind = "Oid"
	KindCurve         NodeKind = "EllipticCurve"
	KindVersion       NodeKind = "Version"
	KindParamSetID    NodeKind = "ParameterSetIdentifier"
	KindFunctionality NodeKind = "Functionality"
)

// Primitive identifies the cryptographic primitive type of an algorithm.
type Primitive string

const (
	PrimitiveBlockCipher         Primitive = "block-cipher"
	PrimitiveStreamCipher        Primitive = "stream-cipher"
	PrimitiveAEAD                Primitive = "ae"
	PrimitiveHash                Primitive = "hash"
	PrimitiveMAC                 Primitive = "mac"
	PrimitiveSignature           Primitive = "signature"
	PrimitivePublicKeyEncryption Primitive = "pke"
	PrimitiveKeyAgreement        Primitive = "key-agree"
	PrimitiveKeyDerivation       Primitive = "kdf"
	PrimitiveKeyEncapsulation    Primitive = "kem"
	PrimitivePasswordHash        Primitive = "pbkdf"
	PrimitivePRNG                Primitive = "drbg"
	PrimitiveXOF                 Primitive = "xof"
	PrimitiveMGF                 Primitive = "mgf"
	PrimitiveUnknown             Primitive = "unknown"
)

// CryptoFunc identifies a cryptographic operation/functionality.
type CryptoFunc string

const (
	FuncEncrypt     CryptoFunc = "encrypt"
	FuncDecrypt     CryptoFunc = "decrypt"
	FuncSign        CryptoFunc = "sign"
	FuncVerify      CryptoFunc = "verify"
	FuncGenerate    CryptoFunc = "generate"
	FuncKeyDerive   CryptoFunc = "keyderive"
	FuncKeyGen      CryptoFunc = "keygen"
	FuncDigest      CryptoFunc = "digest"
	FuncTag         CryptoFunc = "tag"
	FuncEncapsulate CryptoFunc = "encapsulate"
	FuncDecapsulate CryptoFunc = "decapsulate"
	FuncKeyWrap     CryptoFunc = "keywrap"
	FuncKeyUnwrap   CryptoFunc = "keyunwrap"
)

// DetectionLocation holds where in source code a crypto asset was detected.
type DetectionLocation struct {
	FilePath string `json:"filePath"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Bundle   string `json:"bundle"` // e.g. "JCA", "BouncyCastle", "Pyca"
}

// INode is the base interface for all nodes in the crypto asset tree.
type INode interface {
	Kind() NodeKind
	AsString() string
	Children() map[NodeKind]INode
	Put(child INode)
	HasChildOfKind(kind NodeKind) (INode, bool)
}

// BaseNode provides shared children map logic for all concrete node types.
type BaseNode struct {
	children map[NodeKind]INode
}

func NewBaseNode() BaseNode {
	return BaseNode{children: make(map[NodeKind]INode)}
}

func (b *BaseNode) Children() map[NodeKind]INode {
	return b.children
}

func (b *BaseNode) Put(child INode) {
	b.children[child.Kind()] = child
}

func (b *BaseNode) HasChildOfKind(kind NodeKind) (INode, bool) {
	n, ok := b.children[kind]
	return n, ok
}
