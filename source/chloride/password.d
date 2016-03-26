module chloride.password;

import chloride.core;
import chloride.random;

import std.array : uninitializedArray;
import std.algorithm.mutation : copy, fill;
import std.exception: assumeUnique;
import std.string : fromStringz, toStringz;

import sodium.crypto_pwhash_scryptsalsa208sha256;

alias Salt = ubyte[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];

alias PwStringBytes = crypto_pwhash_scryptsalsa208sha256_STRBYTES;

/**
 * Struct containing configuration for password hashing. Specifically the parameters
 * to control the amount of CPU and memory required.
 */
struct PwHashConfig {
    ulong opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
    size_t memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;
}

/**
 * Password hashing config suitable for interactive use.
 */
enum interactivePwHashConfig = PwHashConfig();

/**
 * Password hashing config suitable for highly sensitive data
 */
enum sensitivePwHashConfig = PwHashConfig(
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);

void hashPasswordBuffer(ubyte[] out_, const char[] password, in Salt salt, PwHashConfig config) {
    int result = crypto_pwhash_scryptsalsa208sha256(
        out_.ptr, out_.length,
        password.ptr, password.length,
        salt.ptr, config.opslimit, config.memlimit);
    enforceSodium(result == 0);
}

/**
 * Hash a password with a salt. Returns the hash as a `ubyte[]`.
 */
ubyte[] hashPassword(const char[] password, in Salt salt, PwHashConfig config, size_t length) {
    ubyte[] hash = uninitializedArray!(ubyte[])(length);
    hashPasswordBuffer(hash, password, salt, config);
    return hash;
}

/**
 * Create a string that can be used to store a password safely.
 * It includes the hash, the salt, and information about the CPU and
 * memory limits used to compute it.
 */
string passwordStorageString(string password, PwHashConfig config) {
    char[PwStringBytes] out_ = void;
    int result = crypto_pwhash_scryptsalsa208sha256_str(
        out_, password.ptr, password.length,
        config.opslimit, config.memlimit);
    enforceSodium(result == 0);
    return fromStringz(out_.ptr).idup;
}

/**
 * Verify a password with a hash and salt
 */
bool verifyPassword(const ubyte[] hash, string password, in Salt salt, PwHashConfig config) {
    import core.memory : GC;

    auto hashAttempt = uninitializedArray!(ubyte[])(hash.length);
    scope(exit) {
        GC.free(hashAttempt.ptr);
    }
    hashPasswordBuffer(hashAttempt, password, salt, config);
    return hashAttempt == hash;
}

/**
 * Verify a password against a storage string obtained from `passwordStorageString`
 */
bool verifyPassword(string password, string storageString) {
    char[PwStringBytes] data = void;
    assert(storageString.length < data.length);
    auto tail = storageString.copy(data[]);
    tail[0] = '\0';
    int result = crypto_pwhash_scryptsalsa208sha256_str_verify(data,
                                                              password.ptr, password.length);
    return result == 0;
}

/**
 * Generate a salt suitable for hashing passwords.
 */
Salt makeSalt() {
    Salt salt = void;
    fillRandom(salt);
    return salt;
}

///
unittest {

    auto salt = makeSalt();
    auto hash = hashPassword("password", salt, interactivePwHashConfig, 32);
    assert(verifyPassword(hash, "password", salt, interactivePwHashConfig));
}

///
unittest {
    import std.stdio;
    auto storageString = passwordStorageString("password", interactivePwHashConfig);
    writeln("Hashed Password: ", storageString);
    assert(verifyPassword("password", storageString));

}
