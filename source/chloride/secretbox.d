module chloride.secretbox;

import chloride.core;
import chloride.random : randomArray;

import std.array;

import deimos.sodium.crypto_secretbox;

///
unittest {
    import std.string : representation;
    immutable ubyte[] message = representation("hello");
    immutable key = makeSecretKey();
    auto box = secretBox(message, key);
    assert(openSecretBox(box, key) == message);
}

alias SecretKey = ubyte[crypto_secretbox_KEYBYTES];
alias Nonce = ubyte[crypto_secretbox_NONCEBYTES];
alias SecretMacLength = crypto_secretbox_MACBYTES;

/**
 * A struct containing both the encrypted cipher (using secret key encryption)
 * and the nonce used to encrypt it.
 */
struct SecretBox {
    /// The encrypted message
    ubyte[] ciphertext;
    /// The nonce used to encrypt it (and needed for decryption)
    Nonce nonce;
}

/**
 * Wrapper around `crypto_secretbox_easy`. Encrypts a message using a nonce and key
 * and returns the cipher with MAC as a prefix.
 */
ubyte[] encryptSecretBox(in ubyte[] message,
                         in Nonce nonce,
                         in SecretKey key) {
    auto cipher = uninitializedArray!(ubyte[])(message.length + SecretMacLength);
    auto result = crypto_secretbox_easy(cipher.ptr, message.ptr, message.length,
                          nonce.ptr, key.ptr);
    enforceSodium(result == 0);
    return cipher;
}


/**
 * Wrapper around `crypto_secretbox_open_easy`. Decrypts a cipher using a nonce and key
 * and returns the decrypted message.
 * If decryption fails, null is returned.
 */
ubyte[] decryptSecretBox(in ubyte[] cipher,
                         in Nonce nonce,
                         in SecretKey key) in {
    assert(cipher.length > SecretMacLength);
} body {
    auto message = uninitializedArray!(ubyte[])(cipher.length - SecretMacLength);
    auto result = crypto_secretbox_open_easy(message.ptr, cipher.ptr, cipher.length,
                                             nonce.ptr, key.ptr);
    if (result == 0) {
        return message;
    } else {
        return null;
    }
}
/**
 * Wrapper around `crypto_secretbox_easy` that encrypts in place.
 * `buffer` is changed in place from the message to the cipher. Note
 * that it will be reallocated to be large enough to include the MAC, which
 * may cause the array to be copied.
 */
void encryptSecretBoxInPlace(ref ubyte[] buffer,
                             in Nonce nonce,
                             in SecretKey key) {
    auto messageLen = buffer.length;
    buffer.length += SecretMacLength; // make sure we have enough space for the MAC
    auto result = crypto_secretbox_easy(buffer.ptr, buffer.ptr, messageLen, nonce.ptr, key.ptr);
    enforceSodium(result == 0);
}

/**
 * Wrapper around `crypto_secretbox_open_easy` that decrypts in place.
 * `buffer` is changed in place from the cipher to the decrypted message.
 * If decryption is successful, true is returned and `buffer` is updated with
 * the length of the decrypted message, which will be shorter than the cipher.
 * Otherwise true will be returned.
 */
bool decryptSecretBoxInPlace(ref ubyte[] buffer,
                             in Nonce nonce,
                             in SecretKey key) in {
    assert(buffer.length > SecretMacLength);
} body {
    auto result = crypto_secretbox_open_easy(buffer.ptr, buffer.ptr, buffer.length,
                                             nonce.ptr, key.ptr);
    if (result == 0) {
        buffer = buffer[0 .. $ - SecretMacLength];
        return true;
    } else {
        return false;
    }
}

/**
 * Encrypt `message` using `key` and a newly generated nonce. Return a `SecreBox` with
 * the encrypted ciphertext and the generated nonce.
 */
SecretBox secretBox(in ubyte[] message, in SecretKey key) {
    SecretBox result;
    result.nonce = makeNonce();
    result.ciphertext = encryptSecretBox(message, result.nonce, key);
    return result;
}

/**
 * Decrypt `box` which contains the ciphertext and the nonce used to generate it.
 * If decryption fails it returns null.
 */
ubyte[] openSecretBox(in SecretBox box, in SecretKey key) {
    return decryptSecretBox(box.ciphertext, box.nonce, key);
}

/**
 * Generate a nonce suitable for secret key encryption.
 */
alias makeNonce = randomArray!Nonce;

/**
 * Generate a key suitable for secret key encryption.
 */
alias makeSecretKey = randomArray!SecretKey;
