module chloride.core;

import core.stdc.string : strerror_r;
import core.stdc.errno;

import std.array : uninitializedArray;
import std.string : fromStringz;
import std.exception : assumeUnique;

import sodium.core;

static this() {
    if (sodium_init() == -1) {
        throw new SodiumException("Unable to initialize Sodium");
    }
}

///
class SodiumException : Exception {
    this(string msg,
         string file = __FILE__, size_t line = __LINE__,
         Throwable next = null) pure nothrow @nogc @safe {
        super(msg, file, line, next);
    }

    this(int errno, string file = __FILE__, size_t line = __LINE__) nothrow @trusted {
        auto buf = uninitializedArray!(char[])(256);
        auto errmsg = fromStringz(strerror_r(errno, buf.ptr, buf.length));
        this(assumeUnique(errmsg), file, line);
    }
}

/**
 * enforce a condition, and if it fails throw a `SodiumException` with a message retrieved
 * from the errno.
 */
void enforceSodium(bool condition, string file = __FILE__, size_t line = __LINE__) @safe {
    if (!condition) {
        throw new SodiumException(errno(), file, line);
    }
}
