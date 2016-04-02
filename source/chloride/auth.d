module chloride.auth;

import chloride.core;

import sodium.crypto_auth;

///
unittest {
    import std.string : representation;
    immutable ubyte[] message = representation("hello");
    auto key = makeAuthKey();
    auto mac = authenticateMessage(message, key);
    assert(verifyMac(mac, message, key));
}

alias AuthKey = ubyte[crypto_auth_KEYBYTES];
alias Mac = ubyte[crypto_auth_BYTES];

/**
 * Generate a key for use with authentication.
 */
AuthKey makeAuthKey() {
    import chloride.random : fillRandom;
    AuthKey key = void;
    fillRandom(key);
    return key;
}

/**
 * Create an authentication Mac for a message, signed with `key`.
 */
Mac authenticateMessage(in ubyte[] message, in AuthKey key) {
    Mac mac = void;
    auto result = crypto_auth(mac.ptr, message.ptr, message.length, key.ptr);
    enforceSodium(result == 0);
    return mac;
}

/**
 * Verify message authentication with a secret key.
 */
bool verifyMac(in Mac mac, in ubyte[] message, in AuthKey key) {
    return crypto_auth_verify(mac.ptr, message.ptr, message.length, key.ptr) == 0;
}
