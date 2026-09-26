// Package gossmark is the engine behind the checkmark, in Go.
//
// The api signs credentials and publishes revocation snapshots, so it needs the engine on the
// server as well as on the clients. This is a fifth implementation of the same bytes rather than
// a binding over the C surface, because a Go service linking cgo pays for it everywhere: in the
// build, in cross-compilation for the deployment image, and in every test run. The frozen vectors
// under conformance/vectors are what makes that safe: this package is replayed through exactly
// the same cases as the other four, so a layout that drifted fails the replay rather than failing
// later in the field.
//
// Nothing here knows what anybody is called. A credential's subject is a wallet-bound identifier,
// so a handle may change without touching a badge, and a badge is never a reason to rename anyone.
package gossmark

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Kind is what a credential says. The kind is part of the signed preimage through its domain tag,
// so a credential issued as one kind can never be read as another.
type Kind uint8

const (
	// Individual is Goss vouching for a person. Permanent until revoked.
	Individual Kind = 1
	// Organization is Goss vouching for an organization. Permanent until revoked.
	Organization Kind = 2
	// Capability is Goss permitting an organization to issue staff badges in one category.
	Capability Kind = 3
	// Staff is an organization vouching for its own staff, chaining back to a root.
	Staff Kind = 4
)

// Tag is the domain tag mixed in front of the preimage. Distinct per kind and never reused.
func (k Kind) Tag() string {
	switch k {
	case Individual:
		return "gossmark/v1/individual"
	case Organization:
		return "gossmark/v1/organization"
	case Capability:
		return "gossmark/v1/capability"
	case Staff:
		return "gossmark/v1/staff"
	}
	return ""
}

// CategoryMax is the longest a category may be. A category is a short word from a published list.
const CategoryMax = 32

// PreimageLen is how many bytes a signature is made over. Fixed, because every field is fixed.
const PreimageLen = 1 + 32 + 8 + 20 + CategoryMax + 8 + 8 + 16 + 32

// SignedLen is a credential and its signature, as they travel.
const SignedLen = PreimageLen + ed25519.SignatureSize

// Subject is the subject of every credential: a wallet-bound identifier, never a handle.
type Subject struct {
	// Chain is the EIP-155 id of the chain the address lives on.
	Chain uint64
	// Address is the twenty bytes as they appear on chain.
	Address [20]byte
}

// Credential is one credential, before or after signing.
type Credential struct {
	Kind      Kind
	Issuer    [32]byte
	Subject   Subject
	Category  [CategoryMax]byte
	IssuedAt  int64
	// ExpiresAt is zero for a credential that does not expire. An identity does not lapse on its
	// own; a relationship does, which is why only a staff badge sets this.
	ExpiresAt int64
	ID        [16]byte
	// Delegate is, for a capability, the organization signing key the power is delegated to.
	Delegate [32]byte
}

// ErrCategoryTooLong is returned rather than truncating: a silently shortened category would
// verify against a scope it was never granted.
var ErrCategoryTooLong = errors.New("gossmark: category longer than the field")

// WithCategory returns a copy carrying the category given.
func (c Credential) WithCategory(name string) (Credential, error) {
	if len(name) > CategoryMax {
		return c, ErrCategoryTooLong
	}
	c.Category = [CategoryMax]byte{}
	copy(c.Category[:], name)
	return c, nil
}

// CategoryName is the category as it reads, without its padding.
func (c Credential) CategoryName() string {
	if at := bytes.IndexByte(c.Category[:], 0); at >= 0 {
		return string(c.Category[:at])
	}
	return string(c.Category[:])
}

// Live reports whether the credential is inside its own window at the moment given.
func (c Credential) Live(now int64) bool {
	if now < c.IssuedAt {
		return false
	}
	return c.ExpiresAt == 0 || now < c.ExpiresAt
}

// Preimage writes the bytes a signature is made over: fields in a fixed order, fixed widths,
// integers big-endian. Not a struct encoding and not JSON, so five implementations cannot
// disagree about where a field ends.
func (c Credential) Preimage() [PreimageLen]byte {
	var out [PreimageLen]byte
	at := 0
	out[at] = byte(c.Kind)
	at++
	copy(out[at:], c.Issuer[:])
	at += 32
	binary.BigEndian.PutUint64(out[at:], c.Subject.Chain)
	at += 8
	copy(out[at:], c.Subject.Address[:])
	at += 20
	copy(out[at:], c.Category[:])
	at += CategoryMax
	binary.BigEndian.PutUint64(out[at:], uint64(c.IssuedAt))
	at += 8
	binary.BigEndian.PutUint64(out[at:], uint64(c.ExpiresAt))
	at += 8
	copy(out[at:], c.ID[:])
	at += 16
	copy(out[at:], c.Delegate[:])
	return out
}

func (c Credential) digest() []byte {
	body := c.Preimage()
	h := sha256.New()
	h.Write([]byte(c.Kind.Tag()))
	h.Write(body[:])
	return h.Sum(nil)
}

// Signed is a credential and the signature over it. Neither half means anything alone.
type Signed struct {
	Credential Credential
	Signature  [ed25519.SignatureSize]byte
}

// ErrIssuerMismatch means the credential names one issuer and was handed another's key.
var ErrIssuerMismatch = errors.New("gossmark: credential names a different issuer")

// Sign signs a credential with the issuer's key. The issuer field must already name that key.
func Sign(key ed25519.PrivateKey, cred Credential) (Signed, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(cred.Issuer[:], pub) {
		return Signed{}, ErrIssuerMismatch
	}
	var out Signed
	out.Credential = cred
	copy(out.Signature[:], ed25519.Sign(key, cred.digest()))
	return out, nil
}

// ErrBadSignature means the signature does not verify under the key the credential names.
var ErrBadSignature = errors.New("gossmark: signature does not verify")

// Verify reports whether this credential was signed by the key it names. Nothing else: that a
// signature verifies says who issued it, never that the issuer was allowed to, nor that it is
// still live or unrevoked. Those are the chain's questions.
func Verify(item Signed) error {
	if !ed25519.Verify(ed25519.PublicKey(item.Credential.Issuer[:]), item.Credential.digest(), item.Signature[:]) {
		return ErrBadSignature
	}
	return nil
}

// PutSigned lays a signed credential out for the wire: the preimage exactly as it is signed, then
// the signature, so a reader never rebuilds a preimage and never has a chance to rebuild it
// differently.
func PutSigned(item Signed) [SignedLen]byte {
	var out [SignedLen]byte
	body := item.Credential.Preimage()
	copy(out[:], body[:])
	copy(out[PreimageLen:], item.Signature[:])
	return out
}

// ErrWrongLength means the bytes are not the shape they claim to be.
var ErrWrongLength = errors.New("gossmark: wrong length")

// ErrUnknownKind means a kind byte nobody defined.
var ErrUnknownKind = errors.New("gossmark: unknown kind")

// TakeSigned reads a signed credential off the wire.
func TakeSigned(data []byte) (Signed, error) {
	var item Signed
	if len(data) != SignedLen {
		return item, ErrWrongLength
	}
	at := 0
	kind := Kind(data[at])
	if kind.Tag() == "" {
		return item, ErrUnknownKind
	}
	item.Credential.Kind = kind
	at++
	copy(item.Credential.Issuer[:], data[at:])
	at += 32
	item.Credential.Subject.Chain = binary.BigEndian.Uint64(data[at:])
	at += 8
	copy(item.Credential.Subject.Address[:], data[at:])
	at += 20
	copy(item.Credential.Category[:], data[at:])
	at += CategoryMax
	item.Credential.IssuedAt = int64(binary.BigEndian.Uint64(data[at:]))
	at += 8
	item.Credential.ExpiresAt = int64(binary.BigEndian.Uint64(data[at:]))
	at += 8
	copy(item.Credential.ID[:], data[at:])
	at += 16
	copy(item.Credential.Delegate[:], data[at:])
	at += 32
	copy(item.Signature[:], data[at:])
	return item, nil
}
