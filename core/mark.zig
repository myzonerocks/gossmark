//! gossmark: the engine behind the checkmark.
//!
//! It issues and checks the credentials a badge is made of, and it walks the chain behind one
//! offline: a staff badge is valid because a key signed it that a root key signed the power of,
//! checkable by anyone with no server in the loop.
//!
//! The one rule the whole design follows is visible in what is absent here. Nothing in this
//! engine knows what anybody is called. A credential's subject is a wallet-bound identifier, so
//! a person may change their handle whenever they like and their badge is untouched, and a badge
//! can never be a reason to rename anybody.

const std = @import("std");

pub const cred = @import("cred.zig");
pub const chain = @import("chain.zig");
pub const revoke = @import("revoke.zig");
pub const wire = @import("wire.zig");

pub const Kind = cred.Kind;
pub const Subject = cred.Subject;
pub const Credential = cred.Credential;
pub const Signed = cred.Signed;
pub const Roots = chain.Roots;
pub const Revoked = chain.Revoked;
pub const Verified = chain.Verified;
pub const Snapshot = revoke.Snapshot;
pub const Holder = revoke.Holder;

pub const sign = cred.sign;
pub const verifyDirect = chain.verifyDirect;
pub const verifyStaff = chain.verifyStaff;

test {
    std.testing.refAllDecls(@This());
    _ = cred;
    _ = chain;
    _ = revoke;
    _ = wire;
}
