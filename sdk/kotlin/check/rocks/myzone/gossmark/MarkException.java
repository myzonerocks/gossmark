package rocks.myzone.gossmark;

/** Stands in for the Kotlin class of the same name: the JNI layer throws this one by name. */
public final class MarkException extends RuntimeException {
    public MarkException(String message) { super(message); }
}
