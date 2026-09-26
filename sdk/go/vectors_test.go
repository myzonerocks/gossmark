package gossmark

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The frozen vectors, replayed through this implementation.
//
// This package is a fifth implementation of the same bytes rather than a binding over the C
// surface, and this test is the whole reason that is safe: every case here was recorded by the
// Zig core and is answered again by this code. A field laid out differently, an integer written
// the wrong way round, a domain tag missed, a seed read differently: all of them fail here rather
// than in the field, for one client and not another.
type vector struct {
	Op     string                 `json:"op"`
	Args   map[string]any         `json:"args"`
	Result map[string]any         `json:"result"`
	Check  bool                   `json:"check"`
}

func (v vector) blob(t *testing.T, key string) []byte {
	t.Helper()
	text, ok := v.Args[key].(string)
	if !ok {
		t.Fatalf("%s: arg %q is not a string", v.Op, key)
	}
	out, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("%s: arg %q: %v", v.Op, key, err)
	}
	return out
}

func (v vector) num(t *testing.T, key string) int64 {
	t.Helper()
	value, ok := v.Args[key].(float64)
	if !ok {
		t.Fatalf("%s: arg %q is not a number", v.Op, key)
	}
	return int64(value)
}

func (v vector) expectBlob(t *testing.T, key string) []byte {
	t.Helper()
	text, ok := v.Result[key].(string)
	if !ok {
		t.Fatalf("%s: result %q is not a string", v.Op, key)
	}
	out, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("%s: result %q: %v", v.Op, key, err)
	}
	return out
}

func credFrom(t *testing.T, v vector) Credential {
	t.Helper()
	var cred Credential
	cred.Kind = Kind(v.num(t, "kind"))
	copy(cred.Issuer[:], v.blob(t, "issuer"))
	cred.Subject.Chain = uint64(v.num(t, "subject_chain"))
	copy(cred.Subject.Address[:], v.blob(t, "subject_address"))
	cred.IssuedAt = v.num(t, "issued_at")
	if _, ok := v.Args["expires_at"]; ok {
		cred.ExpiresAt = v.num(t, "expires_at")
	}
	copy(cred.ID[:], v.blob(t, "id"))
	if _, ok := v.Args["delegate"]; ok {
		copy(cred.Delegate[:], v.blob(t, "delegate"))
	}
	name, _ := v.Args["category"].(string)
	out, err := cred.WithCategory(name)
	if err != nil {
		t.Fatalf("%s: category: %v", v.Op, err)
	}
	return out
}

func rootsFrom(t *testing.T, v vector) Roots {
	t.Helper()
	bytes := v.blob(t, "roots")
	if len(bytes) < 4 {
		t.Fatalf("%s: roots too short", v.Op)
	}
	count := int(bytes[3]) | int(bytes[2])<<8 | int(bytes[1])<<16 | int(bytes[0])<<24
	roots := make(Roots, 0, count)
	for i := 0; i < count; i++ {
		var key [32]byte
		copy(key[:], bytes[4+i*32:])
		roots = append(roots, key)
	}
	return roots
}

func revokedFrom(t *testing.T, v vector) Revoked {
	t.Helper()
	text, ok := v.Args["revoked"].(string)
	if !ok {
		return Revoked{}
	}
	bytes, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(bytes) < 4 {
		return Revoked{}
	}
	count := int(bytes[3]) | int(bytes[2])<<8 | int(bytes[1])<<16 | int(bytes[0])<<24
	out := make(Revoked, count)
	for i := 0; i < count; i++ {
		var id [16]byte
		copy(id[:], bytes[4+i*16:])
		out[id] = struct{}{}
	}
	return out
}

func TestFrozenVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "conformance", "vectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	files, replayed := 0, 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		files++
		text, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		var cases []vector
		if err := json.Unmarshal(text, &cases); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		for index, v := range cases {
			if !v.Check {
				continue
			}
			name := entry.Name() + "#" + string(rune('0'+index%10))
			switch v.Op {
			case "public_key":
				key := ed25519.NewKeyFromSeed(v.blob(t, "seed")).Public().(ed25519.PublicKey)
				if got, want := []byte(key), v.expectBlob(t, "key"); string(got) != string(want) {
					t.Fatalf("%s %s: key differs", name, v.Op)
				}
			case "preimage":
				body := credFrom(t, v).Preimage()
				if got, want := body[:], v.expectBlob(t, "preimage"); string(got) != string(want) {
					t.Fatalf("%s %s: the bytes a signature is made over differ from the engine's", name, v.Op)
				}
			case "sign":
				item, err := Sign(ed25519.NewKeyFromSeed(v.blob(t, "seed")), credFrom(t, v))
				if err != nil {
					t.Fatalf("%s %s: %v", name, v.Op, err)
				}
				out := PutSigned(item)
				if got, want := out[:], v.expectBlob(t, "signed"); string(got) != string(want) {
					t.Fatalf("%s %s: signed bytes differ from the engine's", name, v.Op)
				}
			case "verify_direct":
				item, err := TakeSigned(v.blob(t, "signed"))
				if err != nil {
					t.Fatalf("%s %s: %v", name, v.Op, err)
				}
				badge, err := VerifyDirect(item, rootsFrom(t, v), revokedFrom(t, v), v.num(t, "now"))
				if err != nil {
					t.Fatalf("%s %s: %v", name, v.Op, err)
				}
				if want, ok := v.Result["category"].(string); ok && badge.Category != want {
					t.Fatalf("%s %s: category %q, want %q", name, v.Op, badge.Category, want)
				}
			case "verify_staff":
				staff, err := TakeSigned(v.blob(t, "staff"))
				if err != nil {
					t.Fatalf("%s %s: %v", name, v.Op, err)
				}
				capability, err := TakeSigned(v.blob(t, "capability"))
				if err != nil {
					t.Fatalf("%s %s: %v", name, v.Op, err)
				}
				badge, err := VerifyStaff(staff, capability, rootsFrom(t, v), revokedFrom(t, v), v.num(t, "now"))
				if err != nil {
					t.Fatalf("%s %s: %v", name, v.Op, err)
				}
				if badge.Via == nil {
					t.Fatalf("%s %s: a staff badge must carry its organization out", name, v.Op)
				}
			case "snapshot_sign":
				flat := v.blob(t, "ids")
				ids := make([][16]byte, 0, len(flat)/16)
				for at := 0; at+16 <= len(flat); at += 16 {
					var id [16]byte
					copy(id[:], flat[at:])
					ids = append(ids, id)
				}
				key := ed25519.NewKeyFromSeed(v.blob(t, "seed"))
				var issuer [32]byte
				copy(issuer[:], key.Public().(ed25519.PublicKey))
				item, err := SignSnapshot(key, Snapshot{
					Issuer:   issuer,
					Seq:      uint64(v.num(t, "seq")),
					IssuedAt: v.num(t, "issued_at"),
					IDs:      ids,
				})
				if err != nil {
					t.Fatalf("%s %s: %v", name, v.Op, err)
				}
				if got, want := PutSnapshot(item), v.expectBlob(t, "snapshot"); string(got) != string(want) {
					t.Fatalf("%s %s: snapshot bytes differ from the engine's", name, v.Op)
				}
			default:
				continue
			}
			replayed++
		}
	}
	if files == 0 || replayed == 0 {
		t.Fatalf("no vectors replayed: %d files, %d operations", files, replayed)
	}
	t.Logf("replayed %d operations from %d files", replayed, files)
}
