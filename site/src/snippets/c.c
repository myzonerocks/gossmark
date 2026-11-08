#include <gossmark.h>

/* On any status but GM_OK the cell is left empty, so there is nothing to
   show and nothing to free. */
GmBuffer out = {0};
GmStatus st = gm_verify_direct(signed_cred, signed_len,
                               roots, roots_len,
                               revoked, revoked_len,
                               now, &out);
if (st != GM_OK) return st;

use_badge(out.ptr, out.len);
gm_free(&out);
