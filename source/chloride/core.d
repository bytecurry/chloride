module chloride.core;

import std.array : uninitializedArray;
import std.string : fromStringz;
import std.exception : ErrnoException;

import deimos.sodium.core;

static this() {
    if (sodium_init() == -1) {
        throw new SodiumException("Unable to initialize Sodium");
    }
}

/**
 * Exception class for errors that happen in libsodium.
 */
class SodiumException : ErrnoException {
    this(string msg, string file = __FILE__, size_t line = __LINE__) @safe {
        super(msg, file, line);
    }
}

/**
 * enforce a condition, and if it fails throw a `SodiumException` with a message retrieved
 * from the errno.
 */
void enforceSodium(bool condition, string file = __FILE__, size_t line = __LINE__) @safe {
    if (!condition) {
        throw new SodiumException("Sodium error", file, line);
    }
}
