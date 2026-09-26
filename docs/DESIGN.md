# Design

## The rule

Verification never touches a handle. A handle is the person's, permanently, exactly as they chose
it. A badge is a checkmark beside it, never part of it.

Everything else follows from that. The engine is built with no handle in it at all, which is why
the rule cannot be broken by accident later.

## Permanence matches what is certified

An identity does not lapse on its own, so a badge Goss issues directly to a person or an
organization does not expire and is removed only by revocation.

An affiliation is a relationship that can end without anybody reporting it, so a staff badge is
the one kind that expires, on a twelve-month cycle, and the issuing organization has to actively
reconfirm rather than the system relying on revocation alone.

## Delegation is scoped, never total

An organization that can verify people can verify only the category it was approved for. The cap
on how many it may issue is the console's to enforce, because a volume cap cannot be checked from
one credential in isolation; the category can, and is.

## Rotation

The roots are a set rather than a key. A root is rotated on a published schedule, and during a
rotation the old key still has live credentials under it while the new one is already issuing. A
verifier that trusted exactly one key would break every badge on the old one the moment it turned.

## What a client shows

A checkmark, and a panel when it is tapped: who issued it, the category, when. For a staff badge,
the organization and that the organization is itself verified by Goss.

A client should also be able to say how old its revocation snapshot is. An offline check is a real
check, but it is a check against what the client last heard, and pretending otherwise is the one
way this design could mislead somebody.
