package rocks.myzone.gossmark

/**
 * The engine, as Kotlin sees it. Every call goes through one JNI entry, so there is no per-call
 * signature to keep in step with the C surface, and the typing lives here where it can be read.
 *
 * Nothing here fetches and nothing here reads a clock. The roots, the revocation list and the
 * moment are all the caller's, which is what lets a badge be checked offline and what makes a
 * client with a wrong clock fail the same way everywhere.
 *
 * Nothing here knows what anybody is called. A subject is a wallet-bound identifier, so a handle
 * may change without touching a badge.
 */
object Mark {
    /** The four kinds, as the byte at the front of a credential. */
    enum class Kind(val byte: Byte) {
        INDIVIDUAL(1), ORGANIZATION(2), CAPABILITY(3), STAFF(4);

        companion object {
            fun of(byte: Byte): Kind = entries.firstOrNull { it.byte == byte }
                ?: throw MarkException(Status.WRONG_KIND.code)
        }
    }

    /** A wallet-bound identifier. Never a handle. */
    data class Subject(val chain: Long, val address: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Subject && chain == other.chain && address.contentEquals(other.address)

        override fun hashCode(): Int = 31 * chain.hashCode() + address.contentHashCode()
    }

    /** What a badge says once its chain has been walked. */
    data class Badge(
        val kind: Kind,
        val subject: Subject,
        val category: String,
        val issuedAt: Long,
        /** Zero for a badge that does not expire. Only a staff badge carries a real one. */
        val expiresAt: Long,
        val issuer: ByteArray,
        /** For a staff badge, the organization the capability was granted to. */
        val via: Subject?,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Badge && kind == other.kind && subject == other.subject &&
                category == other.category && issuedAt == other.issuedAt &&
                expiresAt == other.expiresAt && issuer.contentEquals(other.issuer) && via == other.via

        override fun hashCode(): Int = listOf(kind, subject, category, issuedAt, expiresAt, issuer.contentHashCode(), via).hashCode()
    }

    val abiVersion: Long get() = number(Native.call(Op.ABI_VERSION, arrayOf(), longArrayOf()))

    /** Read from the library rather than written here, so this binding cannot carry a stale one. */
    val preimageLength: Int get() = number(Native.call(Op.PREIMAGE_LEN, arrayOf(), longArrayOf())).toInt()

    fun publicKey(seed: ByteArray): ByteArray = Native.call(Op.PUBLIC_KEY, arrayOf(seed), longArrayOf())

    fun sign(seed: ByteArray, preimage: ByteArray): ByteArray =
        Native.call(Op.SIGN, arrayOf(seed, preimage), longArrayOf())

    fun verifyDirect(signed: ByteArray, roots: List<ByteArray>, revoked: List<ByteArray>, now: Long): Badge =
        readBadge(Native.call(Op.VERIFY_DIRECT, arrayOf(signed, list(roots, 32), list(revoked, 16)), longArrayOf(now)))

    fun verifyStaff(staff: ByteArray, capability: ByteArray, roots: List<ByteArray>, revoked: List<ByteArray>, now: Long): Badge =
        readBadge(Native.call(Op.VERIFY_STAFF, arrayOf(staff, capability, list(roots, 32), list(revoked, 16)), longArrayOf(now)))

    /** What a server does. A client only ever opens one. */
    fun signSnapshot(seed: ByteArray, seq: Long, issuedAt: Long, ids: List<ByteArray>): ByteArray =
        Native.call(Op.SNAPSHOT_SIGN, arrayOf(seed, flat(ids, 16)), longArrayOf(seq, issuedAt))

    /**
     * Takes a snapshot newer than the one held. An older or equal sequence throws STALE: replaying
     * an earlier list must never bring a revoked badge back.
     */
    fun openSnapshot(snapshot: ByteArray, roots: List<ByteArray>, heldSeq: Long): Snapshot {
        val bytes = Native.call(Op.SNAPSHOT_OPEN, arrayOf(snapshot, list(roots, 32)), longArrayOf(heldSeq))
        val seq = readLong(bytes, 0)
        val issuedAt = readLong(bytes, 8)
        val ids = (16 until bytes.size step 16).map { bytes.copyOfRange(it, it + 16) }
        return Snapshot(ids, seq, issuedAt)
    }

    data class Snapshot(val ids: List<ByteArray>, val seq: Long, val issuedAt: Long)

    private fun number(bytes: ByteArray): Long = readLong(bytes, 0)

    private fun readLong(bytes: ByteArray, at: Int): Long {
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (bytes[at + i].toLong() and 0xFF)
        return value
    }

    /** A list as the C surface takes it: a big-endian count, then each fixed-width item. */
    private fun list(items: List<ByteArray>, width: Int): ByteArray {
        val kept = items.filter { it.size == width }
        val out = ByteArray(4 + kept.size * width)
        for (i in 0 until 4) out[i] = (kept.size ushr ((3 - i) * 8)).toByte()
        kept.forEachIndexed { index, item -> item.copyInto(out, 4 + index * width) }
        return out
    }

    private fun flat(items: List<ByteArray>, width: Int): ByteArray {
        val kept = items.filter { it.size == width }
        val out = ByteArray(kept.size * width)
        kept.forEachIndexed { index, item -> item.copyInto(out, index * width) }
        return out
    }

    private fun readBadge(bytes: ByteArray): Badge {
        var at = 0
        fun take(n: Int): ByteArray = bytes.copyOfRange(at, at + n).also { at += n }
        fun long(): Long = readLong(bytes, at).also { at += 8 }

        val kind = Kind.of(bytes[at]); at += 1
        val subject = Subject(long(), take(20))
        val raw = take(32)
        val end = raw.indexOfFirst { it == 0.toByte() }.let { if (it < 0) raw.size else it }
        val category = String(raw, 0, end, Charsets.UTF_8)
        val issuedAt = long()
        val expiresAt = long()
        val issuer = take(32)
        val hasVia = bytes[at] == 1.toByte(); at += 1
        val viaChain = long()
        val viaAddress = take(20)
        return Badge(kind, subject, category, issuedAt, expiresAt, issuer, if (hasVia) Subject(viaChain, viaAddress) else null)
    }
}

/** The status a failed call carried. The same numbers the C surface answers. */
enum class Status(val code: Int) {
    OK(0), BAD_ARGUMENT(1), BAD_SIGNATURE(2), UNTRUSTED_ISSUER(3), NOT_LIVE(4), REVOKED(5),
    WRONG_KIND(6), OUT_OF_SCOPE(7), NO_DELEGATE(8), STALE(9), OUT_OF_MEMORY(10), INTERNAL(11);

    companion object {
        fun of(code: Int): Status = entries.firstOrNull { it.code == code } ?: INTERNAL
    }
}

class MarkException(val code: Int) : RuntimeException(Status.of(code).name) {
    val status: Status get() = Status.of(code)
}

/** The one JNI entry. Every operation is a number, its inputs byte arrays, its numbers longs. */
internal object Native {
    init {
        System.loadLibrary("gossmark_jni")
    }

    @JvmStatic
    external fun call(op: Int, args: Array<ByteArray>, nums: LongArray): ByteArray
}

internal object Op {
    const val ABI_VERSION = 0
    const val PREIMAGE_LEN = 1
    const val SIGNED_LEN = 2
    const val VERIFIED_LEN = 3
    const val PUBLIC_KEY = 4
    const val SIGN = 5
    const val VERIFY_DIRECT = 6
    const val VERIFY_STAFF = 7
    const val SNAPSHOT_SIGN = 8
    const val SNAPSHOT_OPEN = 9
}
