/* Signs a badge and checks it back, with nothing but the header and the static library.
 * The point of the example is the shape of a check: the caller hands in its roots, its
 * revocation list and the moment, and the library answers without reaching for anything. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "gossmark.h"

int main(void) {
    uint8_t seed[32];
    memset(seed, 7, sizeof seed);

    GmBuffer key = {0};
    assert(gm_public_key(seed, sizeof seed, &key) == GM_OK);

    /* The preimage, laid out exactly as the header describes: kind, issuer, chain, address,
     * category, issued, expires, id, delegate. */
    const size_t preimage_len = gm_preimage_len();
    uint8_t body[256];
    assert(preimage_len <= sizeof body);
    memset(body, 0, preimage_len);
    size_t at = 0;
    body[at++] = (uint8_t)GM_INDIVIDUAL;
    memcpy(body + at, key.ptr, 32); at += 32;
    for (int i = 7; i >= 0; i--) body[at + (size_t)(7 - i)] = (uint8_t)(1ull >> (i * 8));
    at += 8;
    memset(body + at, 0xA1, 20); at += 20;
    memcpy(body + at, "creator", 7); at += 32;
    at += 8;  /* issued_at zero */
    at += 8;  /* never expires */
    memset(body + at, 0xD1, 16); at += 16;
    at += 32; /* no delegate */
    assert(at == preimage_len);

    GmBuffer signed_cred = {0};
    assert(gm_sign(seed, sizeof seed, body, preimage_len, &signed_cred) == GM_OK);

    uint8_t roots[4 + 32];
    memset(roots, 0, 4);
    roots[3] = 1;
    memcpy(roots + 4, key.ptr, 32);
    uint8_t none[4] = {0, 0, 0, 0};

    GmBuffer seen = {0};
    GmStatus status = gm_verify_direct(signed_cred.ptr, signed_cred.len, roots, sizeof roots,
                                       none, sizeof none, 1000, &seen);
    assert(status == GM_OK);
    assert(seen.len == gm_verified_len());
    assert(seen.ptr[0] == (uint8_t)GM_INDIVIDUAL);

    /* The same badge against roots it was not signed under: refused, and nothing written. */
    uint8_t stranger[4 + 32];
    memset(stranger, 0, sizeof stranger);
    stranger[3] = 1;
    GmBuffer nothing = {0};
    assert(gm_verify_direct(signed_cred.ptr, signed_cred.len, stranger, sizeof stranger,
                            none, sizeof none, 1000, &nothing) == GM_UNTRUSTED_ISSUER);
    assert(nothing.ptr == NULL);

    gm_free(&seen);
    gm_free(&signed_cred);
    gm_free(&key);
    printf("gossmark: signed a badge and checked it back\n");
    return 0;
}
