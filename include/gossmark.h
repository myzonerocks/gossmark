/* gossmark: the C surface. Inputs are a pointer and a length, NULL with zero meaning absent.
 * Byte outputs are GmBuffer cells the library fills; free each once with gm_free. Every call
 * returns a GmStatus, zero on success, and on any other status every output cell is left empty.
 *
 * Nothing here fetches and nothing here reads a clock. A verifier is handed its roots, its
 * revocation snapshot and the moment to check against, which is what lets a badge be checked
 * offline and lets a client with a wrong clock fail the same way everywhere.
 *
 * Nothing here knows what anybody is called. A credential's subject is a wallet-bound
 * identifier, so a handle may change without touching a badge. */
#ifndef GOSSMARK_H
#define GOSSMARK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GM_ABI_VERSION 1u

typedef struct GmBuffer {
    uint8_t *ptr;
    size_t len;
} GmBuffer;

typedef enum GmStatus {
    GM_OK = 0,
    GM_BAD_ARGUMENT = 1,
    GM_BAD_SIGNATURE = 2,
    GM_UNTRUSTED_ISSUER = 3,
    GM_NOT_LIVE = 4,
    GM_REVOKED = 5,
    GM_WRONG_KIND = 6,
    GM_OUT_OF_SCOPE = 7,
    GM_NO_DELEGATE = 8,
    GM_STALE = 9,
    GM_OUT_OF_MEMORY = 10,
    GM_INTERNAL = 11
} GmStatus;

/* The kind byte at the front of a credential. */
typedef enum GmKind {
    GM_INDIVIDUAL = 1,
    GM_ORGANIZATION = 2,
    GM_CAPABILITY = 3,
    GM_STAFF = 4
} GmKind;

/* The ABI this library speaks. A host reading a different number should call nothing else. */
uint32_t gm_abi_version(void);

/* Hands back a buffer the library gave. Safe on a cell that was never filled, and on NULL. */
void gm_free(GmBuffer *cell);

/* Room for a host to write an input into, for a host with no heap of its own to lend (wasm).
 * Freed with gm_dealloc, never with gm_free: this is the caller's memory, not a filled cell. */
uint8_t *gm_alloc(size_t len);
void gm_dealloc(uint8_t *ptr, size_t len);

/* Fixed wire lengths, so a host can size a check before it makes one. */
size_t gm_preimage_len(void);
size_t gm_signed_len(void);
size_t gm_verified_len(void);

/* The public key a 32-byte seed belongs to. An issuer names its key inside every credential it
 * signs, so a host needs this before it can build one. */
GmStatus gm_public_key(const uint8_t *seed, size_t seed_len, GmBuffer *out);

/* Signs a credential. In: the preimage exactly as this library lays it out. Out: that preimage
 * followed by its signature. The issuer named inside must be the key the seed belongs to, so a
 * credential can never claim one issuer and be signed by another. */
GmStatus gm_sign(const uint8_t *seed, size_t seed_len,
                 const uint8_t *cred, size_t cred_len,
                 GmBuffer *out);

/* Checks a badge Goss signed itself. Roots are a big-endian uint32 count then that many 32-byte
 * keys; revoked is a big-endian uint32 count then that many 16-byte ids. Out is a verified badge
 * of gm_verified_len() bytes. */
GmStatus gm_verify_direct(const uint8_t *signed_cred, size_t signed_len,
                          const uint8_t *roots, size_t roots_len,
                          const uint8_t *revoked, size_t revoked_len,
                          int64_t now, GmBuffer *out);

/* Checks a badge an organization issued, walking its capability back to a root. The scope is
 * checked here rather than trusted: an organization approved for one category cannot issue for
 * another. Revoking the capability's id refuses every badge that flowed from it at once. */
GmStatus gm_verify_staff(const uint8_t *staff, size_t staff_len,
                         const uint8_t *capability, size_t capability_len,
                         const uint8_t *roots, size_t roots_len,
                         const uint8_t *revoked, size_t revoked_len,
                         int64_t now, GmBuffer *out);

/* Signs a revocation snapshot over the ids given, which are a flat run of 16-byte values. */
GmStatus gm_snapshot_sign(const uint8_t *seed, size_t seed_len,
                          uint64_t seq, int64_t issued_at,
                          const uint8_t *ids, size_t ids_len,
                          GmBuffer *out);

/* Checks a snapshot against the roots and, if it is newer than held_seq, writes its ids out as a
 * flat run of 16-byte values. An older or equal sequence answers GM_STALE: replaying an earlier
 * list must never bring a revoked badge back. out_seq and out_issued_at may be NULL. */
GmStatus gm_snapshot_open(const uint8_t *snapshot, size_t snapshot_len,
                          const uint8_t *roots, size_t roots_len,
                          uint64_t held_seq,
                          GmBuffer *out_ids, uint64_t *out_seq, int64_t *out_issued_at);

#ifdef __cplusplus
}
#endif

#endif /* GOSSMARK_H */
