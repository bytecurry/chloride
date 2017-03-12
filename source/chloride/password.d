module chloride.password;

import chloride.core;
import chloride.random : randomArray;

import std.array : uninitializedArray;
import std.algorithm.mutation : copy, fill;
import std.exception: assumeUnique;
import std.string : fromStringz, toStringz;

import sodium.crypto_pwhash_scryptsalsa208sha256;
import sodium.crypto_pwhash;

/**
 * Algorithm to use for the password hashing.
 */
enum Algorithm {
  Scrypt,
  Argon2
}

/**
 * Struct containing configuration for password hashing. Specifically the parameters
 * to control the amount of CPU and memory required.
 */
struct PwHashConfig {
  ulong opslimit;
  size_t memlimit;
}

template PwHash(Algorithm alg) {
  static if (alg == Algorithm.Scrypt) {
    alias Salt = ubyte[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    alias PwStringBytes = crypto_pwhash_scryptsalsa208sha256_STRBYTES;

    /**
     * Password hashing config suitable for interactive use.
     */
    enum interactivePwHashConfig = PwHashConfig(
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    /**
     * Password hashing config suitable for highly sensitive data
     */
    enum sensitivePwHashConfig = PwHashConfig(
        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
  } else static if (alg == Algorithm.Argon2) {
    alias Salt = ubyte[crypto_pwhash_SALTBYTES];
    alias PwStringBytes = crypto_pwhash_STRBYTES;

    /**
     * Password hashing config suitable for interactive use.
     */
    enum interactivePwHashConfig = PwHashConfig(
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE);
    /**
     * Password hashing config suitable for moderate use.
     */
    enum moderatePwHashConfig = PwHashConfig(
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE);

    /**
     * Password hashing config suitable for highly sensitive data.
     */
    enum sensitivePwHashConfig = PwHashConfig(
        crypto_pwhash_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE);

  }

  void hashPasswordBuffer(ubyte[] out_, in char[] password, in Salt salt, PwHashConfig config) {
    static if( alg == Algorithm.Scrypt ) {
      int result = crypto_pwhash_scryptsalsa208sha256(
          out_.ptr, out_.length,
          password.ptr, password.length,
          salt.ptr, config.opslimit, config.memlimit);
    } else static if (alg == Algorithm.Argon2) {
      int result = crypto_pwhash(
          out_.ptr, out_.length,
          password.ptr, password.length,
          salt.ptr, config.opslimit, config.memlimit,
          crypto_pwhash_ALG_DEFAULT);
    }
    enforceSodium(result == 0);
  }

  /**
   * Create a string that can be used to store a password safely.
   * It includes the hash, the salt, and information about the CPU and
   * memory limits used to compute it.
   */
  string hashPassword(string password, PwHashConfig config) {
    char[PwStringBytes] out_ = void;
    static if (alg == Algorithm.Scrypt) {
      int result = crypto_pwhash_scryptsalsa208sha256_str(
          out_, password.ptr, password.length,
          config.opslimit, config.memlimit);
    } else static if (alg == Algorithm.Argon2) {
      int result = crypto_pwhash_str(
          out_, password.ptr, password.length,
          config.opslimit, config.memlimit);
    }
    enforceSodium(result == 0);
    return fromStringz(out_.ptr).idup;
  }

  /**
   * Hash a password with a salt. Returns the hash as a `ubyte[]`.
   */
  ubyte[] hashPassword(in char[] password, in Salt salt, PwHashConfig config, size_t length) {
      ubyte[] hash = uninitializedArray!(ubyte[])(length);
      hashPasswordBuffer(hash, password, salt, config);
      return hash;
  }

  /**
   * Verify a password against a storage string obtained from `hashPassword`
   */
  bool verifyPassword(string password, string storageString) {
    char[PwStringBytes] data = '\0';
    assert(storageString.length < data.length);
    storageString.copy(data[]);
    static if (alg == Algorithm.Scrypt) {
      int result = crypto_pwhash_scryptsalsa208sha256_str_verify(data,
          password.ptr, password.length);
    } else static if (alg == Algorithm.Argon2) {
      int result = crypto_pwhash_str_verify(data,
          password.ptr, password.length);
    }
    return result == 0;
  }


  /**
   * Verify a password with a hash and salt
   */
  bool verifyPassword(in ubyte[] hash, string password, in Salt salt, PwHashConfig config) {
    import core.memory : GC;

    auto hashAttempt = uninitializedArray!(ubyte[])(hash.length);
    scope(exit) {
      GC.free(hashAttempt.ptr);
    }
    hashPasswordBuffer(hashAttempt, password, salt, config);
    return hashAttempt == hash;
  }

  /**
   * Generate a salt suitable for hashing passwords.
   */
  alias makeSalt = randomArray!Salt;

  ///
  unittest {
    auto salt = makeSalt();
    auto hash = hashPassword("password", salt, interactivePwHashConfig, 32);
    assert(verifyPassword(hash, "password", salt, interactivePwHashConfig));
  }

  ///
  unittest {
    import std.stdio;
    auto storageString = hashPassword("password", interactivePwHashConfig);
    writeln("Hashed Password: ", storageString);
    assert(verifyPassword("password", storageString));
  }
}

alias Argon2 = PwHash!(Algorithm.Argon2);
alias Scrypt = PwHash!(Algorithm.Scrypt);


/**
 * Convenience function to hash a password.
 *
 * If the algorithm isn't supplied use Argon2 as the default.
 */
string hashPassword(Algorithm alg, string password, PwHashConfig config) {
    final switch (alg) {
        case Algorithm.Argon2:
            return Argon2.hashPassword(password, config);
        case Algorithm.Scrypt:
            return Scrypt.hashPassword(password, config);
    }
}

/// ditto
string hashPassword(string password, PwHashConfig config) {
    return Argon2.hashPassword(password, config);
}


/**
 * Convenience function to verify a password.
 */
bool verifyPassword(Algorithm alg, string password, string hash) {
    final switch (alg) {
        case Algorithm.Argon2:
            return Argon2.verifyPassword(password, hash);
        case Algorithm.Scrypt:
            return Scrypt.verifyPassword(password, hash);
    }
}

/**
 * Verify a passwod with a hash string.
 *
 * This will attempt to determine the correct algorithm from a prefix
 * in the hash. If the prefix isn't known it will return false.
 */
bool verifyPassword(string password, string hash) {
    import std.algorithm.searching;
    import std.conv;
    import sodium.crypto_pwhash_argon2i;

    const ARGON_PREFIX = to!string(crypto_pwhash_argon2i_STRPREFIX);
    const SCRYPT_PREFIX = to!string(crypto_pwhash_scryptsalsa208sha256_STRPREFIX);

    // figure out which algorithm was used
    if (hash.startsWith(ARGON_PREFIX)) {
        return Argon2.verifyPassword(password, hash);
    } else if (hash.startsWith(SCRYPT_PREFIX)) {
        return Scrypt.verifyPassword(password, hash);
    } else {
        return false;
    }
}

///
unittest {
    auto hash = Scrypt.hashPassword("password", Scrypt.interactivePwHashConfig);
    assert(verifyPassword("password", hash));
    assert(!verifyPassword("bad pass", hash));
}

///
unittest {
    auto hash = Argon2.hashPassword("password", Argon2.interactivePwHashConfig);
    assert(verifyPassword("password", hash));
    assert(!verifyPassword("bad pass", hash));
}
