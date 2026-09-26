package gossmark

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Roots are the keys a verifier trusts to begin with, and the only thing it has to be told out of
// band. More than one, because a root is rotated on a published schedule: during a rotation the
// old key still has live credentials under it while the new one is already issuing.
type Roots [][32]byte

// Trusts reports whether a key is one of the roots.
func (r Roots) Trusts(key [32]byte) bool {
	for _, known := range r {
		if bytes.Equal(known[:], key[:]) {
			return true
		}
	}
	return false
}

// Revoked is what the caller knows to be revoked. The engine never fetches it: a verifier holds
// the newest signed snapshot it has seen and answers from that, so a check works offline and a
// stale snapshot is the caller's to notice rather than a silent pass.
type Revoked map[[16]byte]struct{}

// Has reports whether an id is in the set.
func (r Revoked) Has(id [16]byte) bool {
	_, gone := r[id]
	return gone
}

// The chain's refusals. Each says exactly which link failed.
var (
	ErrUntrustedIssuer = errors.New("gossmark: issuer is not trusted here")
	ErrNotLive         = errors.New("gossmark: outside its own window")
	ErrRevoked         = errors.New("gossmark: revoked")
	ErrWrongKind       = errors.New("gossmark: wrong kind for this question")
	ErrOutOfScope      = errors.New("gossmark: outside the scope the organization was granted")
	ErrNoDelegate      = errors.New("gossmark: capability delegates to no key")
)

// Badge is what a verified credential says once the whole chain has been walked. A caller draws
// from this and never from a credential alone, because a credential alone has not been checked.
type Badge struct {
	Kind      Kind
	Subject   Subject
	Category  string
	IssuedAt  int64
	ExpiresAt int64
	// Issuer is the key that signed the badge: a root for a direct badge, the organization for a
	// staff badge. What the panel shows when somebody taps the checkmark.
	Issuer [32]byte
	// Via is, for a staff badge, the organization the capability was granted to.
	Via *Subject
}

// VerifyDirect checks a badge Goss signed itself. Nothing about a handle is consulted, here or
// anywhere below.
func VerifyDirect(item Signed, roots Roots, revoked Revoked, now int64) (Badge, error) {
	switch item.Credential.Kind {
	case Individual, Organization:
	default:
		return Badge{}, ErrWrongKind
	}
	if !roots.Trusts(item.Credential.Issuer) {
		return Badge{}, ErrUntrustedIssuer
	}
	if err := Verify(item); err != nil {
		return Badge{}, err
	}
	if !item.Credential.Live(now) {
		return Badge{}, ErrNotLive
	}
	if revoked.Has(item.Credential.ID) {
		return Badge{}, ErrRevoked
	}
	return Badge{
		Kind:      item.Credential.Kind,
		Subject:   item.Credential.Subject,
		Category:  item.Credential.CategoryName(),
		IssuedAt:  item.Credential.IssuedAt,
		ExpiresAt: item.Credential.ExpiresAt,
		Issuer:    item.Credential.Issuer,
	}, nil
}

// VerifyStaff checks a badge an organization issued, walking its capability back to a root:
//
//	the capability is signed by a root key and is live and unrevoked,
//	the staff badge is signed by the very key that capability delegates to,
//	the staff badge's category is the one the capability was granted for.
//
// The last is the scope, checked here rather than trusted. And because every staff badge runs
// through the capability, revoking that one id refuses all of them at once without touching a
// single staff badge.
func VerifyStaff(staff, capability Signed, roots Roots, revoked Revoked, now int64) (Badge, error) {
	if staff.Credential.Kind != Staff || capability.Credential.Kind != Capability {
		return Badge{}, ErrWrongKind
	}
	if !roots.Trusts(capability.Credential.Issuer) {
		return Badge{}, ErrUntrustedIssuer
	}
	if err := Verify(capability); err != nil {
		return Badge{}, err
	}
	if !capability.Credential.Live(now) {
		return Badge{}, ErrNotLive
	}
	if revoked.Has(capability.Credential.ID) {
		return Badge{}, ErrRevoked
	}

	var zero [32]byte
	if bytes.Equal(capability.Credential.Delegate[:], zero[:]) {
		return Badge{}, ErrNoDelegate
	}
	if !bytes.Equal(staff.Credential.Issuer[:], capability.Credential.Delegate[:]) {
		return Badge{}, ErrUntrustedIssuer
	}
	if err := Verify(staff); err != nil {
		return Badge{}, err
	}
	if !staff.Credential.Live(now) {
		return Badge{}, ErrNotLive
	}
	if revoked.Has(staff.Credential.ID) {
		return Badge{}, ErrRevoked
	}
	if staff.Credential.CategoryName() != capability.Credential.CategoryName() {
		return Badge{}, ErrOutOfScope
	}

	via := capability.Credential.Subject
	return Badge{
		Kind:      Staff,
		Subject:   staff.Credential.Subject,
		Category:  staff.Credential.CategoryName(),
		IssuedAt:  staff.Credential.IssuedAt,
		ExpiresAt: staff.Credential.ExpiresAt,
		Issuer:    staff.Credential.Issuer,
		Via:       &via,
	}, nil
}

// SnapshotTag is the domain tag a revocation snapshot is signed under, distinct from every
// credential tag so neither can ever be read as the other.
const SnapshotTag = "gossmark/v1/revocations"

// Snapshot is what has been revoked, as of a moment, signed by a root.
//
// The list is whole rather than a delta. A delta stream has to be replayed in order from a known
// point, and a client that missed one shows a revoked checkmark until it notices; a whole list
// cannot be behind in a way that shows too much.
type Snapshot struct {
	Issuer   [32]byte
	Seq      uint64
	IssuedAt int64
	IDs      [][16]byte
}

// SignedSnapshot is a snapshot and the signature over it.
type SignedSnapshot struct {
	Snapshot  Snapshot
	Signature [ed25519.SignatureSize]byte
}

func (s Snapshot) digest() []byte {
	h := sha256.New()
	h.Write([]byte(SnapshotTag))
	h.Write(s.Issuer[:])
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], s.Seq)
	h.Write(scratch[:])
	binary.BigEndian.PutUint64(scratch[:], uint64(s.IssuedAt))
	h.Write(scratch[:])
	// The count is signed as well as the ids, so a list cannot be truncated and still verify.
	binary.BigEndian.PutUint64(scratch[:], uint64(len(s.IDs)))
	h.Write(scratch[:])
	for _, id := range s.IDs {
		h.Write(id[:])
	}
	return h.Sum(nil)
}

// SignSnapshot signs a revocation snapshot with a root key.
func SignSnapshot(key ed25519.PrivateKey, snapshot Snapshot) (SignedSnapshot, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(snapshot.Issuer[:], pub) {
		return SignedSnapshot{}, ErrIssuerMismatch
	}
	var out SignedSnapshot
	out.Snapshot = snapshot
	copy(out.Signature[:], ed25519.Sign(key, snapshot.digest()))
	return out, nil
}

// VerifySnapshot reports whether a snapshot was signed by a root this verifier trusts.
func VerifySnapshot(item SignedSnapshot, roots Roots) error {
	if !roots.Trusts(item.Snapshot.Issuer) {
		return ErrUntrustedIssuer
	}
	if !ed25519.Verify(ed25519.PublicKey(item.Snapshot.Issuer[:]), item.Snapshot.digest(), item.Signature[:]) {
		return ErrBadSignature
	}
	return nil
}

// SnapshotLen is how long a snapshot of this many ids is on the wire.
func SnapshotLen(count int) int {
	return 32 + 8 + 8 + 4 + count*16 + ed25519.SignatureSize
}

// PutSnapshot lays a signed snapshot out for the wire.
func PutSnapshot(item SignedSnapshot) []byte {
	out := make([]byte, SnapshotLen(len(item.Snapshot.IDs)))
	at := 0
	copy(out[at:], item.Snapshot.Issuer[:])
	at += 32
	binary.BigEndian.PutUint64(out[at:], item.Snapshot.Seq)
	at += 8
	binary.BigEndian.PutUint64(out[at:], uint64(item.Snapshot.IssuedAt))
	at += 8
	binary.BigEndian.PutUint32(out[at:], uint32(len(item.Snapshot.IDs)))
	at += 4
	for _, id := range item.Snapshot.IDs {
		copy(out[at:], id[:])
		at += 16
	}
	copy(out[at:], item.Signature[:])
	return out
}
