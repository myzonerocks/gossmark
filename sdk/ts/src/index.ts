// The web binding: the wasm32 core reached through linear memory. Every call here is the C
// surface with the buffer handling done once, so a caller never frees anything and never sees a
// pointer.
//
// Nothing here fetches and nothing here reads a clock. The roots, the revocation list and the
// moment are all the caller's, which is what lets a badge be checked offline and what makes a
// client with a wrong clock fail the same way everywhere.

/** The four kinds, as the byte at the front of a credential. */
export const Kind = {
  individual: 1,
  organization: 2,
  capability: 3,
  staff: 4,
} as const
export type Kind = (typeof Kind)[keyof typeof Kind]

/** A wallet-bound identifier. Never a handle: a handle is a display name its owner may change. */
export interface Subject {
  chain: bigint
  address: Uint8Array
}

/** What a badge says once its chain has been walked. */
export interface Badge {
  kind: Kind
  subject: Subject
  category: string
  issuedAt: bigint
  /** Zero for a badge that does not expire. Only a staff badge carries a real one. */
  expiresAt: bigint
  issuer: Uint8Array
  /** For a staff badge, the organization the capability was granted to. */
  via: Subject | null
}

export const Status = {
  ok: 0,
  badArgument: 1,
  badSignature: 2,
  untrustedIssuer: 3,
  notLive: 4,
  revoked: 5,
  wrongKind: 6,
  outOfScope: 7,
  noDelegate: 8,
  stale: 9,
  outOfMemory: 10,
  internal: 11,
} as const

const names: Record<number, string> = {
  1: 'badArgument', 2: 'badSignature', 3: 'untrustedIssuer', 4: 'notLive', 5: 'revoked',
  6: 'wrongKind', 7: 'outOfScope', 8: 'noDelegate', 9: 'stale', 10: 'outOfMemory', 11: 'internal',
}

export class MarkError extends Error {
  readonly status: number
  constructor(status: number) {
    super(names[status] ?? `status ${status}`)
    this.name = 'MarkError'
    this.status = status
  }
}

interface Exports {
  memory: WebAssembly.Memory
  gm_abi_version(): number
  gm_preimage_len(): number
  gm_signed_len(): number
  gm_verified_len(): number
  gm_free(cell: number): void
  gm_public_key(seed: number, seedLen: number, out: number): number
  gm_sign(seed: number, seedLen: number, cred: number, credLen: number, out: number): number
  gm_verify_direct(s: number, sl: number, r: number, rl: number, v: number, vl: number, now: bigint, out: number): number
  gm_verify_staff(st: number, stl: number, c: number, cl: number, r: number, rl: number, v: number, vl: number, now: bigint, out: number): number
  gm_snapshot_sign(seed: number, seedLen: number, seq: bigint, at: bigint, ids: number, idsLen: number, out: number): number
  gm_snapshot_open(s: number, sl: number, r: number, rl: number, held: bigint, outIds: number, outSeq: number, outAt: number): number
  // The core allocates every output itself; these two give the host a place to put its inputs.
  gm_alloc(len: number): number
  gm_dealloc(ptr: number, len: number): void
}

/**
 * The engine, loaded once. Instantiate with the bytes of `gossmark.wasm`:
 *
 *   const mark = await Mark.load(await fetch(url).then(r => r.arrayBuffer()))
 */
export class Mark {
  private readonly wasm: Exports
  /** What this call borrowed from the core, handed back whether the call succeeded or not. */
  private borrowed: Array<[number, number]> = []

  private constructor(wasm: Exports) {
    this.wasm = wasm
  }

  static async load(bytes: BufferSource): Promise<Mark> {
    // Bun's ambient types resolve instantiate to the Module overload, which answers an Instance
    // rather than a source holding one. The runtime shape is the source, so the cast goes through
    // unknown and the shape is named on the way out instead of destructured blind.
    const answer = (await WebAssembly.instantiate(bytes, {})) as unknown as { instance: WebAssembly.Instance }
    return new Mark(answer.instance.exports as unknown as Exports)
  }

  get abiVersion(): number {
    return this.wasm.gm_abi_version()
  }

  /** How long the bytes a signature is made over are. Read from the core, never written here. */
  get preimageLength(): number {
    return this.wasm.gm_preimage_len()
  }

  publicKey(seed: Uint8Array): Uint8Array {
    return this.call((out) => {
      const [p, n] = this.put(seed)
      return this.wasm.gm_public_key(p, n, out)
    })
  }

  sign(seed: Uint8Array, preimage: Uint8Array): Uint8Array {
    return this.call((out) => {
      const [s, sn] = this.put(seed)
      const [c, cn] = this.put(preimage)
      return this.wasm.gm_sign(s, sn, c, cn, out)
    })
  }

  verifyDirect(signed: Uint8Array, roots: Uint8Array[], revoked: Uint8Array[], now: bigint): Badge {
    const bytes = this.call((out) => {
      const [s, sn] = this.put(signed)
      const [r, rn] = this.put(list(roots, 32))
      const [v, vn] = this.put(list(revoked, 16))
      return this.wasm.gm_verify_direct(s, sn, r, rn, v, vn, now, out)
    })
    return this.readBadge(bytes)
  }

  verifyStaff(staff: Uint8Array, capability: Uint8Array, roots: Uint8Array[], revoked: Uint8Array[], now: bigint): Badge {
    const bytes = this.call((out) => {
      const [st, stn] = this.put(staff)
      const [c, cn] = this.put(capability)
      const [r, rn] = this.put(list(roots, 32))
      const [v, vn] = this.put(list(revoked, 16))
      return this.wasm.gm_verify_staff(st, stn, c, cn, r, rn, v, vn, now, out)
    })
    return this.readBadge(bytes)
  }

  /** What a server does. A client only ever opens one. */
  signSnapshot(seed: Uint8Array, seq: bigint, issuedAt: bigint, ids: Uint8Array[]): Uint8Array {
    return this.call((out) => {
      const [s, sn] = this.put(seed)
      const [i, ins] = this.put(flat(ids, 16))
      return this.wasm.gm_snapshot_sign(s, sn, seq, issuedAt, i, ins, out)
    })
  }

  /**
   * Takes a snapshot newer than the one held. An older or equal sequence throws `stale`:
   * replaying an earlier list must never bring a revoked badge back.
   */
  openSnapshot(snapshot: Uint8Array, roots: Uint8Array[], heldSeq: bigint): { ids: Uint8Array[]; seq: bigint; issuedAt: bigint } {
    let seq = 0n
    let issuedAt = 0n
    const bytes = this.call((out) => {
      const [s, sn] = this.put(snapshot)
      const [r, rn] = this.put(list(roots, 32))
      const seqCell = this.reserve(8)
      const atCell = this.reserve(8)
      const status = this.wasm.gm_snapshot_open(s, sn, r, rn, heldSeq, out, seqCell, atCell)
      if (status === Status.ok) {
        // Read while the cells are still borrowed: they are the core's memory again once the
        // call ends, and a value read after that is whatever happens to be there.
        const view = new DataView(this.wasm.memory.buffer)
        seq = view.getBigUint64(seqCell, true)
        issuedAt = view.getBigInt64(atCell, true)
      }
      return status
    })
    const ids: Uint8Array[] = []
    for (let at = 0; at < bytes.length; at += 16) ids.push(bytes.slice(at, at + 16))
    return { ids, seq, issuedAt }
  }

  // The buffer handling, done once.

  private call(body: (out: number) => number): Uint8Array {
    const cell = this.reserve(8)
    try {
      const status = body(cell)
      if (status !== Status.ok) throw new MarkError(status)
      const view = new DataView(this.wasm.memory.buffer)
      const ptr = view.getUint32(cell, true)
      const len = view.getUint32(cell + 4, true)
      // Copied out before the cell is freed: the view is a window onto the core's memory, and
      // that memory is the core's again the moment gm_free returns.
      const copy = new Uint8Array(this.wasm.memory.buffer, ptr, len).slice()
      this.wasm.gm_free(cell)
      return copy
    } finally {
      this.release()
    }
  }

  /** Room in the core's memory, handed back at the end of the call whatever happened. */
  private reserve(n: number): number {
    const at = this.wasm.gm_alloc(n)
    if (at === 0) throw new MarkError(Status.outOfMemory)
    this.borrowed.push([at, n])
    new Uint8Array(this.wasm.memory.buffer, at, n).fill(0)
    return at
  }

  private put(data: Uint8Array): [number, number] {
    if (data.length === 0) return [0, 0]
    const at = this.reserve(data.length)
    new Uint8Array(this.wasm.memory.buffer, at, data.length).set(data)
    return [at, data.length]
  }

  private release(): void {
    for (const [ptr, len] of this.borrowed) this.wasm.gm_dealloc(ptr, len)
    this.borrowed = []
  }

  private readBadge(bytes: Uint8Array): Badge {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    let at = 0
    const kind = bytes[at] as Kind
    at += 1
    const chain = view.getBigUint64(at, false)
    at += 8
    const address = bytes.slice(at, at + 20)
    at += 20
    const raw = bytes.slice(at, at + 32)
    at += 32
    const end = raw.indexOf(0)
    const category = new TextDecoder().decode(end === -1 ? raw : raw.subarray(0, end))
    const issuedAt = view.getBigInt64(at, false)
    at += 8
    const expiresAt = view.getBigInt64(at, false)
    at += 8
    const issuer = bytes.slice(at, at + 32)
    at += 32
    const hasVia = bytes[at] === 1
    at += 1
    const viaChain = view.getBigUint64(at, false)
    at += 8
    const viaAddress = bytes.slice(at, at + 20)
    return {
      kind, subject: { chain, address }, category, issuedAt, expiresAt, issuer,
      via: hasVia ? { chain: viaChain, address: viaAddress } : null,
    }
  }
}

/** A list as the C surface takes it: a big-endian count, then each fixed-width item. */
function list(items: Uint8Array[], width: number): Uint8Array {
  const kept = items.filter((i) => i.length === width)
  const out = new Uint8Array(4 + kept.length * width)
  new DataView(out.buffer).setUint32(0, kept.length, false)
  kept.forEach((item, index) => out.set(item, 4 + index * width))
  return out
}

function flat(items: Uint8Array[], width: number): Uint8Array {
  const kept = items.filter((i) => i.length === width)
  const out = new Uint8Array(kept.length * width)
  kept.forEach((item, index) => out.set(item, index * width))
  return out
}
