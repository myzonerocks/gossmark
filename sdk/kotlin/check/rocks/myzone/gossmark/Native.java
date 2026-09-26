package rocks.myzone.gossmark;

/** The one JNI entry, declared exactly as the Kotlin binding declares it. */
public final class Native {
    static { System.loadLibrary("gossmark_jni"); }
    public static native byte[] call(int op, byte[][] args, long[] nums);
}
