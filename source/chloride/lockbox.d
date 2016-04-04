module chloride.lockbox;

import chloride.core;
import chloride.random : randomArray;

import std.array : uninitializedArray;

import sodium.crypto_box;

///
unittest {
    import std.string : representation;
    immutable ubyte[] message = representation("hello");
    auto alice = makeKeyPair();
    auto bob = makeKeyPair();
    auto box = lockBox(message, bob.publicKey, alice.privateKey);
    assert(openLockBox(box, alice.publicKey, bob.privateKey) == message);
}

///
unittest {
    import std.string : representation;
    immutable ubyte[] message = representation("hello");
    auto keys = makeKeyPair();
    auto box = sealBox(message, keys.publicKey);
    assert(openSealedBox(box, keys) == message);
}

alias PublicKey = ubyte[crypto_box_PUBLICKEYBYTES];
alias PrivateKey = ubyte[crypto_box_SECRETKEYBYTES];
alias LockBoxSeed = ubyte[crypto_box_SEEDBYTES];
alias Nonce = ubyte[crypto_box_NONCEBYTES];
alias LockBoxMacLength = crypto_box_MACBYTES;

/**
 * Struct containing a key pair for public key encryption
 */
struct KeyPair {
    PublicKey publicKey;
    PrivateKey privateKey;
}

/**
 * Generate a new random key pair.
 */
KeyPair makeKeyPair() {
    KeyPair pair;
    auto result = crypto_box_keypair(pair.publicKey.ptr, pair.privateKey.ptr);
    enforceSodium(result == 0);
    return pair;
}

/**
 * Generate a key pair from a seed.
 */
KeyPair makeKeyPair(in LockBoxSeed seed) {
    KeyPair pair;
    auto result = crypto_box_seed_keypair(pair.publicKey.ptr,
                                          pair.privateKey.ptr,
                                          seed.ptr);
    enforceSodium(result == 0);
    return pair;
}

/**
 * Generate a seed suitable for use with makeKeyPair
 */
alias makeLockBoxSeed = randomArray!LockBoxSeed;

/**
 * Generate a nonce suitable for encrypting a lock box.
 */
alias makeNonce = randomArray!Nonce;

/**
 * Struct containing a message encrypted and signed using public key cryptography.
 * Includes the ciphertext and the nonce used to encrypt it.
 */
struct LockBox {
    /// The encrypted message
    ubyte[] ciphertext;
    /// The nonce used to encrypt it (and needed for decryption)
    Nonce nonce;
}

/**
 * Encrypt a message using a public key for the recipient  (`pk`) and signed with the private key of the
 * sender `sk`.
 */
ubyte[] encryptLockBox(in ubyte[] message, in Nonce nonce, in PublicKey pk, in PrivateKey sk) {
    auto cipher = uninitializedArray!(ubyte[])(message.length + LockBoxMacLength);
    auto result = crypto_box_easy(cipher.ptr, message.ptr, message.length,
                                  nonce.ptr, pk.ptr, sk.ptr);
    enforceSodium(result == 0);
    return cipher;
}

/**
 * Decrypt a message using a private key for the recipient (`sk`) and verify the signature with the public
 * key of the sender (`pk`). Returns null if decryption or verification failed.
 */
ubyte[] decryptLockBox(in ubyte[] cipher, in Nonce nonce, in PublicKey pk, in PrivateKey sk) in {
    assert(cipher.length > LockBoxMacLength);
} body {
    auto message = uninitializedArray!(ubyte[])(cipher.length - LockBoxMacLength);
    auto result = crypto_box_open_easy(message.ptr, cipher.ptr, cipher.length,
                                       nonce.ptr, pk.ptr, sk.ptr);
    if (result == 0) {
        return message;
    } else {
        return null;
    }
}

/**
 * Encrypt and sign `message` using public key cryptography. The message
 * is encrypted using the public key of the recipient (`pk`) and signed with
 * the private key of the sender (`sk`).
 */
LockBox lockBox(in ubyte[] message, in PublicKey pk, in PrivateKey sk) {
    LockBox result = {nonce: makeNonce()};
    result.ciphertext = encryptLockBox(message, result.nonce, pk, sk);
    return result;
}

/**
 * Decrypt a LockBox encrypted and signed using public key cryptography.
 * The message is decrypted using the private key of the recipient (`sk`) and
 * the signature is verified using the public key of the sender (`pk`).
 * If decryption or verification fails, null is returned.
 */
ubyte[] openLockBox(in LockBox box, in PublicKey pk, in PrivateKey sk) {
    return decryptLockBox(box.ciphertext, box.nonce, pk, sk);
}

/**
 * Anonymously encrypt a message using the recipients public key. A new key pair is generated for
 * each invocation, so a nonce isn't needed.
 */
ubyte[] sealBox(in ubyte[] message, in PublicKey pk) {
    auto cipher = uninitializedArray!(ubyte[])(message.length + crypto_box_SEALBYTES);
    auto result = crypto_box_seal(cipher.ptr, message.ptr, message.length, pk.ptr);
    enforceSodium(result == 0);
    return cipher;
}

/**
 * Decrypt a sealed box using the recipient's key pair.
 * If decryption fails, return null.
 */
ubyte[] openSealedBox(in ubyte[] cipher, in KeyPair keys) in {
    assert(cipher.length > crypto_box_SEALBYTES);
} body {
    auto message = uninitializedArray!(ubyte[])(cipher.length - crypto_box_SEALBYTES);
    auto result = crypto_box_seal_open(message.ptr, cipher.ptr, cipher.length,
                                       keys.publicKey.ptr, keys.privateKey.ptr);
    if (result == 0) {
        return message;
    } else {
        return null;
    }
}
