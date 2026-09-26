//! The wasm32 root: the C ABI reached through linear memory by the web package. Nothing here
//! needs randomness or a clock from the host, because the engine asks for neither: a caller
//! hands in the moment to check against and the lists to check against, so a badge verifies the
//! same way in a browser as it does on a phone.
comptime {
    _ = @import("gossmark.zig");
}
