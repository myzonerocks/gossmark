import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { Kind, Mark, MarkError, Status } from '../src/index'

const wasm = readFileSync(new URL('../wasm/gossmark.wasm', import.meta.url))
const engine = await Mark.load(wasm)

/** The preimage, laid out the way the engine lays it out. Written by hand on purpose: a client
 *  that lays it out differently is exactly what the frozen vectors exist to catch, and this is
 *  the web client's copy of that layout. */
function preimage(o: {
  kind: number; issuer: Uint8Array; address: number; category: string
  issuedAt: bigint; expiresAt?: bigint; id: number; delegate?: Uint8Array
}): Uint8Array {
  const body = new Uint8Array(engine.preimageLength)
  const view = new DataView(body.buffer)
  body[0] = o.kind
  body.set(o.issuer, 1)
  view.setBigUint64(33, 1n, false)
  body.fill(o.address, 41, 61)
  body.set(new TextEncoder().encode(o.category), 61)
  view.setBigInt64(93, o.issuedAt, false)
  view.setBigInt64(101, o.expiresAt ?? 0n, false)
  body.fill(o.id, 109, 125)
  if (o.delegate) body.set(o.delegate, 125)
  return body
}

const seedOf = (b: number) => new Uint8Array(32).fill(b)

describe('the web binding', () => {
  test('speaks the abi the core was built with', () => {
    expect(engine.abiVersion).toBe(1)
    expect(engine.preimageLength).toBe(157)
  })

  test('a badge verifies under its root', () => {
    const seed = seedOf(1)
    const root = engine.publicKey(seed)
    const signed = engine.sign(seed, preimage({ kind: Kind.individual, issuer: root, address: 0xa1, category: 'journalist', issuedAt: 100n, id: 0xd1 }))
    const badge = engine.verifyDirect(signed, [root], [], 500n)
    expect(badge.kind).toBe(Kind.individual)
    expect(badge.category).toBe('journalist')
    expect(badge.expiresAt).toBe(0n)
    expect(badge.via).toBeNull()
  })

  test('a badge outside the roots is refused', () => {
    const seed = seedOf(2)
    const key = engine.publicKey(seed)
    const signed = engine.sign(seed, preimage({ kind: Kind.individual, issuer: key, address: 0xa2, category: 'creator', issuedAt: 100n, id: 0xd2 }))
    expect(() => engine.verifyDirect(signed, [new Uint8Array(32).fill(9)], [], 500n))
      .toThrow(new MarkError(Status.untrustedIssuer))
  })

  test('a staff badge walks its capability and its scope holds', () => {
    const rootSeed = seedOf(11)
    const orgSeed = seedOf(22)
    const root = engine.publicKey(rootSeed)
    const org = engine.publicKey(orgSeed)
    const capability = engine.sign(rootSeed, preimage({ kind: Kind.capability, issuer: root, address: 0xb2, category: 'journalist', issuedAt: 100n, expiresAt: 10_000n, id: 0xc3, delegate: org }))
    const staff = engine.sign(orgSeed, preimage({ kind: Kind.staff, issuer: org, address: 0xe4, category: 'journalist', issuedAt: 100n, expiresAt: 5_000n, id: 0xd4 }))

    const badge = engine.verifyStaff(staff, capability, [root], [], 500n)
    expect(badge.kind).toBe(Kind.staff)
    expect(badge.via).not.toBeNull()

    const intern = engine.sign(orgSeed, preimage({ kind: Kind.staff, issuer: org, address: 0xe5, category: 'intern', issuedAt: 100n, expiresAt: 5_000n, id: 0xd5 }))
    expect(() => engine.verifyStaff(intern, capability, [root], [], 500n))
      .toThrow(new MarkError(Status.outOfScope))
  })

  test('pulling the capability takes every badge that flowed from it', () => {
    const rootSeed = seedOf(11)
    const orgSeed = seedOf(22)
    const root = engine.publicKey(rootSeed)
    const org = engine.publicKey(orgSeed)
    const capability = engine.sign(rootSeed, preimage({ kind: Kind.capability, issuer: root, address: 0xb2, category: 'journalist', issuedAt: 100n, expiresAt: 10_000n, id: 0xc3, delegate: org }))
    const staff = engine.sign(orgSeed, preimage({ kind: Kind.staff, issuer: org, address: 0xe4, category: 'journalist', issuedAt: 100n, expiresAt: 5_000n, id: 0xd4 }))
    expect(() => engine.verifyStaff(staff, capability, [root], [new Uint8Array(16).fill(0xc3)], 500n))
      .toThrow(new MarkError(Status.revoked))
  })

  test('an older snapshot cannot be replayed over a newer one', () => {
    const seed = seedOf(11)
    const root = engine.publicKey(seed)
    const signed = engine.signSnapshot(seed, 7n, 900n, [new Uint8Array(16).fill(0xab)])
    const opened = engine.openSnapshot(signed, [root], 0n)
    expect(opened.seq).toBe(7n)
    expect(opened.ids.length).toBe(1)
    expect(() => engine.openSnapshot(signed, [root], 7n)).toThrow(new MarkError(Status.stale))
  })
})

describe('a deployment that has revoked nobody', () => {
  // The web client threw on every page load for this: an empty list answered a sentinel pointer
  // past the end of memory, and a typed array built at that offset throws whatever its length
  // is. Nothing must read as nothing, all the way out.
  test('opens an empty snapshot without throwing', () => {
    const seed = seedOf(11)
    const root = engine.publicKey(seed)
    const signed = engine.signSnapshot(seed, 1n, 900n, [])
    const opened = engine.openSnapshot(signed, [root], 0n)
    expect(opened.ids).toEqual([])
    expect(opened.seq).toBe(1n)
    expect(opened.issuedAt).toBe(900n)
  })

  // And a badge still checks out against it, which is the whole point: a box that has revoked
  // nobody should verify everybody it issued to.
  test('still verifies a badge against it', () => {
    const seed = seedOf(11)
    const root = engine.publicKey(seed)
    const signed = engine.sign(seed, preimage({ kind: Kind.individual, issuer: root, address: 0xa7, category: 'creator', issuedAt: 100n, id: 0xd7 }))
    const opened = engine.openSnapshot(engine.signSnapshot(seed, 1n, 900n, []), [root], 0n)
    const badge = engine.verifyDirect(signed, [root], opened.ids, 500n)
    expect(badge.category).toBe('creator')
  })
})
