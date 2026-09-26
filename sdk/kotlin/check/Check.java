import java.nio.ByteBuffer;
import java.util.Base64;
import rocks.myzone.gossmark.Native;

/**
 * The JNI round trip, proved rather than assumed. The Kotlin binding compiles inside the app, so
 * it is known to build; nothing had ever run it, so nothing knew whether a call across the
 * boundary comes back with the right bytes.
 */
public final class Check {
    static long u64(byte[] b, int at) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[at + i] & 0xFF);
        return v;
    }

    public static void main(String[] argv) throws Exception {
        byte[] none = new byte[0];
        byte[][] noArgs = new byte[0][];
        long[] noNums = new long[0];

        long abi = u64(Native.call(0, noArgs, noNums), 0);
        long preimageLen = u64(Native.call(1, noArgs, noNums), 0);
        System.out.println("abi " + abi + " | preimage " + preimageLen);
        if (abi != 1 || preimageLen != 157) throw new AssertionError("the library answers a shape this binding does not speak");

        byte[] seed = new byte[32];
        java.util.Arrays.fill(seed, (byte) 11);
        byte[] key = Native.call(4, new byte[][]{seed}, noNums);
        if (key.length != 32) throw new AssertionError("a public key is thirty-two bytes, got " + key.length);

        // The same credential the frozen vectors carry: an individual badge, issued by that key.
        byte[] body = new byte[(int) preimageLen];
        body[0] = 1;
        System.arraycopy(key, 0, body, 1, 32);
        ByteBuffer.wrap(body, 33, 8).putLong(1L);
        java.util.Arrays.fill(body, 41, 61, (byte) 0xA1);
        byte[] cat = "journalist".getBytes("UTF-8");
        System.arraycopy(cat, 0, body, 61, cat.length);
        ByteBuffer.wrap(body, 93, 8).putLong(100L);
        java.util.Arrays.fill(body, 109, 125, (byte) 0xD1);

        byte[] signed = Native.call(5, new byte[][]{seed, body}, noNums);
        if (signed.length != preimageLen + 64) throw new AssertionError("a signed credential is the preimage and its signature");

        byte[] roots = new byte[4 + 32];
        roots[3] = 1;
        System.arraycopy(key, 0, roots, 4, 32);
        byte[] revoked = new byte[4];

        byte[] seen = Native.call(6, new byte[][]{signed, roots, revoked}, new long[]{500L});
        if (seen[0] != 1) throw new AssertionError("kind came back as " + seen[0]);
        String category = new String(seen, 29, 10, "UTF-8");
        if (!category.equals("journalist")) throw new AssertionError("category came back as " + category);

        // A root it was not signed under must be refused, as an exception rather than a value.
        byte[] stranger = new byte[4 + 32];
        stranger[3] = 1;
        try {
            Native.call(6, new byte[][]{signed, stranger, revoked}, new long[]{500L});
            throw new AssertionError("a badge outside the roots must not verify");
        } catch (RuntimeException expected) {
            // The JNI layer throws the status across, which is what the Kotlin binding types.
        }

        // And an empty snapshot, which is the state every deployment starts in and the shape that
        // threw in the web binding.
        byte[] snapshot = Native.call(8, new byte[][]{seed, none}, new long[]{1L, 900L});
        byte[] opened = Native.call(9, new byte[][]{snapshot, roots}, new long[]{0L});
        if (u64(opened, 0) != 1L) throw new AssertionError("sequence came back as " + u64(opened, 0));
        if (opened.length != 16) throw new AssertionError("an empty list carries no ids, got " + (opened.length - 16));

        System.out.println("jni: signed, verified, refused a stranger, and opened an empty snapshot");
    }
}
