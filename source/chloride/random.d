module chloride.random;

import chloride.core;

import std.array : uninitializedArray;
import std.traits;

import sodium.randombytes;


/**
 * Allocate `n` bytes of cryptographic random data.
 */
ubyte[] randomBytes(int n) {
    ubyte[] buf = uninitializedArray!(ubyte[])(n);
    fillRandom(buf);
    return buf;
}

/**
 * Create an array of `n` elements filled with random data.
 * The array can be static or dynamic. If the array is dynamic, the size
 * must be passed as a runtime argument.
 */
U randomArray(U: T[n], T, int n)() if (isScalarType!T) {
    U data = void;
    fillRandom(data);
    return data;
}

///
U randomArray(U: T[], T)(int n) if (isScalarType!T) {
    U data = uninitializedArray!(U)(n);
    fillRandom(data);
    return data;
}


/**
 * Fill `buf` with cryptographic random data.
 */
void fillRandom(void[] buf) {
    randombytes_buf(buf.ptr, buf.length);
}

/**
 * Get a single random Integer of type T. T can be any
 * integral type with four or fewer bytes.
 */
T random(T)() if (isIntegral!T && (T.sizeof < 4)) {
    uint bytes = random(Unsigned!T.max);
    return cast(T) bytes;
}

/// ditto
T random(T : uint = uint)() {
    return randombytes_random();
}

/**
 * Get a random integer between 0 and n (excluded). It does its best
 * to guarantee a uniform distribution.
 */
uint random(uint n) {
    return randombytes_uniform(n);
}


/**
 * An input range that generates random bytes.
 */
struct RandomByteRange {
    private uint data;
    private ubyte count;

    @property ubyte front() const pure {
        return cast(ubyte) data;
    }

    void popFront() {
        count++;
        if (count < 4) {
            data >>= 8;
        } else {
            count = 0;
            data = random();
        }
    }

    enum empty = false;
}

/**
 * Create an instance of RandomByteRange
 */
RandomByteRange randomByteRange() {
    return RandomByteRange(random(), 0);
}
