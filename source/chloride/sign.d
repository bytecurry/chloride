module chloride.sign;

import chloride.core;
import chloride.random : randomArray;

import std.array : uninitializedArray;

import sodium.crypto_sign;

///
unittest {
    import std.string : representation;
    immutable ubyte[] message = representation("hello");
    auto keys = makeSigningKeys();
    auto signed = signMessage(message, keys.privateKey);
    assert(openSignedMessage(signed, keys.publicKey) == message);
}

///
unittest {
    import std.string : representation;
    immutable ubyte[] message = representation("hello");
    auto keys = makeSigningKeys();
    auto sig = messageSignature(message, keys.privateKey);
    assert(verifySignature(message, sig, keys.publicKey));
}

alias SignPublicKey = ubyte[crypto_sign_PUBLICKEYBYTES];
alias SignPrivateKey = ubyte[crypto_sign_SECRETKEYBYTES];
alias SigningSeed = ubyte[crypto_sign_SEEDBYTES];
alias SignatureLength = crypto_sign_BYTES;

struct SigningKeys {
    SignPublicKey publicKey;
    SignPrivateKey privateKey;
}

/**
 * Generate a new random key pair suitable for public key signatures.
 */
SigningKeys makeSigningKeys() {
    SigningKeys pair;
    auto result = crypto_sign_keypair(pair.publicKey.ptr, pair.privateKey.ptr);
    enforceSodium(result == 0);
    return pair;
}

/**
 * Generate a key pair from a seed.
 */
SigningKeys makeSigningKeys(in SigningSeed seed) {
    SigningKeys pair;
    auto result = crypto_sign_seed_keypair(pair.publicKey.ptr, pair.privateKey.ptr, seed.ptr);
    enforceSodium(result == 0);
    return pair;
}

/**
 * Generate a seed that can be used to generate key pairs with `makeSigningKeys`.
 */
alias makeSigningSeed = randomArray!SigningSeed;

/**
 * Sign a message using a private key by prepending a signature to the message.
 */
ubyte[] signMessage(in ubyte[] message, in SignPrivateKey key) {
    ubyte[] sm = uninitializedArray!(ubyte[])(message.length + SignatureLength);
    auto result = crypto_sign(sm.ptr, null, message.ptr, message.length, key.ptr);
    enforceSodium(result == 0);
    return sm;
}

/**
 * Compute a signature for a message using a private key. Unlike `signMessage`
 * this does not include the original message.
 */
ubyte[SignatureLength] messageSignature(in ubyte[] message, in SignPrivateKey key) {
    ubyte[SignatureLength] signature = void;
    auto result = crypto_sign_detached(signature.ptr, null, message.ptr, message.length, key.ptr);
    enforceSodium(result == 0);
    return signature;
}

/**
 * Verify a signed message using the public key corresponding to the private
 * key used to sign it. If verification succeeds return the message (without the signature),
 * otherwise return null.
 */
ubyte[] openSignedMessage(in ubyte[] signed, in SignPublicKey key) in {
    assert(signed.length > SignatureLength);
} body {
    ubyte[] message = uninitializedArray!(ubyte[])(signed.length - SignatureLength);
    if (crypto_sign_open(message.ptr, null, signed.ptr, signed.length, key.ptr) == 0) {
        return message;
    } else {
        return null;
    }
}

/**
 * Verify a signed message using the public key corresponding to the private key
 * used to sign it. Returns true on success and false on failure. This method is passed
 * the message and signature separately.
 */
bool verifySignature(in ubyte[] message, in ubyte[SignatureLength] signature, in SignPublicKey key) {
    return crypto_sign_verify_detached(signature.ptr, message.ptr, message.length, key.ptr) == 0;
}
