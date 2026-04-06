package model

import "strconv"

// --- Numeric property nodes ---

type IntProperty struct {
	BaseNode
	Value    int      `json:"value"`
	PropKind NodeKind `json:"-"`
}

func newIntProp(v int, kind NodeKind) *IntProperty {
	return &IntProperty{BaseNode: NewBaseNode(), Value: v, PropKind: kind}
}

func (p *IntProperty) Kind() NodeKind   { return p.PropKind }
func (p *IntProperty) AsString() string { return strconv.Itoa(p.Value) }

func NewKeyLength(bits int) *IntProperty   { return newIntProp(bits, KindKeyLength) }
func NewBlockSize(bits int) *IntProperty   { return newIntProp(bits, KindBlockSize) }
func NewDigestSize(bits int) *IntProperty  { return newIntProp(bits, KindDigestSize) }
func NewTagLength(bits int) *IntProperty   { return newIntProp(bits, KindTagLength) }
func NewNonceLength(bits int) *IntProperty { return newIntProp(bits, KindNonceLength) }
func NewSaltLength(bits int) *IntProperty  { return newIntProp(bits, KindSaltLength) }
func NewIVLength(bits int) *IntProperty    { return newIntProp(bits, KindIVLength) }

// --- String property nodes ---

type StringProperty struct {
	BaseNode
	Value    string   `json:"value"`
	PropKind NodeKind `json:"-"`
}

func newStrProp(v string, kind NodeKind) *StringProperty {
	return &StringProperty{BaseNode: NewBaseNode(), Value: v, PropKind: kind}
}

func (p *StringProperty) Kind() NodeKind   { return p.PropKind }
func (p *StringProperty) AsString() string { return p.Value }

func NewMode(name string) *StringProperty          { return newStrProp(name, KindMode) }
func NewPadding(name string) *StringProperty       { return newStrProp(name, KindPadding) }
func NewOid(oid string) *StringProperty            { return newStrProp(oid, KindOid) }
func NewEllipticCurve(name string) *StringProperty { return newStrProp(name, KindCurve) }
func NewVersion(ver string) *StringProperty        { return newStrProp(ver, KindVersion) }
func NewParamSetID(id string) *StringProperty      { return newStrProp(id, KindParamSetID) }
