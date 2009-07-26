/*!
 *  gruft-sha256 module Version 0.0.8-2009xxyy Copyright (c) 2009 Nikola Klaric.
 *
 *  Licensed under the Academic Free License 3.0 (AFL 3.0).
 *
 *  For the full license text see the enclosed LICENSE.TXT, or go to:
 *  http://opensource.org/licenses/afl-3.0.php
 *
 *  This software is part of the gruft cryptography library project:
 *  http://www.getgruft.org/
 *
 *  If you are using this library for commercial purposes, we encourage you
 *  to purchase a commercial license. Please visit the gruft project homepage
 *  for more details.
 *
 *  The SHA-256 algorithm was designed by the National Security Agency (NSA).
 */

/**
 * @namespace gruft.*
 */
var gruft; if (typeof(gruft) !== typeof(Object.prototype)) { gruft = {}; }

/**
 * 
 */
gruft.SHA256 = function () {
    if (typeof(gruft.common) !== typeof(gruft)) {
        throw new Error("module <gruft.common> not found");
    }
    gruft.common.reflect(this, gruft.__SHA256__, arguments);
    this.selftest();
};

/**
 *
 */
gruft.__SHA256__ = function () {
    if (this instanceof gruft.__SHA256__) {
        this.__init__.apply(this, arguments);
    }
};

/**
 *
 */
gruft.__SHA256__.prototype = {

    __name__    : "gruft.SHA256",
    __repr__    : "SHA-256",    
    __author__  : "Nikola Klaric",
    __version__ : "0.0.8",

    /**
     * Initialize this instance of <gruft.__SHA256__> and set up internal objects.
     */
    __init__: function () { 
    
    },

    /**
     * Perform self-test using discrete test vectors.
     * 
     * @exception {gruft.TypeError} Raised if __digest__() is not a valid function.
     * @exception {gruft.AssertionError} Raised if a test vector fails.
     */
    selftest: function () {
        if (typeof(this.__digest__) !== typeof(this.selftest)) {
            throw gruft.TypeError("<%s.__digest__> is not callable", this.__name__);
        }

        var digest = this.__digest__, gc = gruft.common, error = "SHA-256 digest of test vector %s is erroneous",
            failUnlessEqual = gc.failUnlessEqual, getTestvector = gc.getTestvector, clipString = gc.clipString;

        /* Basic. */
        failUnlessEqual(
            digest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            error, "'' (empty string)");
        failUnlessEqual(
            digest(getTestvector("digest-base64")),
            "e173d43de98094098259467ff632b4fc61496af96f3a354a006360d246e8166f",
            error, "{digest-base64}");

        /* 24 chars between 0x00 .. 0x80 .. 0xff. */
        failUnlessEqual(
            digest(getTestvector("digest-span-utf8")),
            "00ae9a702783ce4b028ea876dd0bc04945ffa94ed7c4eb0d0d99bf574fec3d7b",
            error, "{digest-span-utf8}");

        /* 24 chars between 0x0000 .. 0x8000 .. 0xffff. */
        failUnlessEqual(
            digest(getTestvector("digest-span-utf16")),
            "7c413b7ff6ff4b8e921f571c374f98c7145582931cdf4953e0188873f1e7036c",
            error, "{digest-span-utf16} (implicitly clipped to byte-sized characters)");
        failUnlessEqual(digest(getTestvector("digest-span-utf16")), 
            digest(clipString(getTestvector("digest-span-utf16"))),
            error, "{digest-span-utf16} (explicitly clipped to byte-sized characters)");

        /* 1024 zeros. */
        failUnlessEqual(
            digest(getTestvector("digest-1024x0")),
            "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
            error, "{digest-1024x0}");

        /* 1031 randomly selected (but stable) chars. */
        failUnlessEqual(
            digest(getTestvector("digest-random")),
            "e498f0465fb2533f44546b29aa60cbd13e6c7144d21c9bcf04af8648984a054f",
            error, "{digest-random}");

        /* Format to byte sequence. */
        failUnlessEqual(
            digest({message:"SHA-256", format:"byteseq"}),
            [0xbb, 0xd0, 0x7c, 0x4f, 0xc0, 0x2c, 0x99, 0xb9, 0x71, 0x24, 0xfe, 0xbf, 0x42, 0xc7, 0xb6, 0x3b,
             0x50, 0x11, 0xc0, 0xdf, 0x28, 0xd4, 0x09, 0xfb, 0xb4, 0x86, 0xb5, 0xa9, 0xd2, 0xe6, 0x15, 0xea],
             error, "'SHA-256' (formatted to byte sequence)");

        /* Format to base64. */
        failUnlessEqual(
            digest({message:"ABCDE"}),
            "f0393febe8baaa55e32f7be2a7cc180bf34e52137d99e056c817a9c07b8f239a",
            error, "'ABCDE' (formatted to hex string)");
        failUnlessEqual(
            digest({message:"ABCDE", format:"base64"}),
            "8Dk/6+i6qlXjL3vip8wYC/NOUhN9meBWyBepwHuPI5o=",
            error, "'ABCDE' (formatted to base64)");
        failUnlessEqual(
            digest("ABCDE", {format:"base64_safe"}),
            "8Dk-6*i6qlXjL3vip8wYC-NOUhN9meBWyBepwHuPI5o",
            error, "'ABCDE' (formatted to base64, URL-safe)");
    },

    /**
     * Compress message to SHA-256 digest in pure Javascript.
     * 
     * @param {String} message The string to compress. 
     * @return {Array} SHA-256 digest as an 8-tuple of 32-bit words.
     */
    __digest__: function (message) {
        var bits = message.length * 8, chunks = 16 + ((bits + 64 >> 9) << 4), padded = 16 + chunks + 64 - 1,
            x = new Array(padded), n = -1;
        while (++n < padded) { x[n] = 0; } // TODO: optimize and take care of empty message string
        for (n = 0; n < bits; n += 8) {
            /* Clip to byte-sized characters. */
            x[n >> 5] |= (message.charCodeAt(n / 8) & 0xff) << 24 - n % 32;
        }

        /* Apply MD5 padding (big-bit-endian, big-byte-endian, left-justified). */
        x[bits >> 5] |= 0x80 << 24 - bits % 32;
        x[chunks - 1] = bits;

        var a, b, c, d, e, f, g, h, t0, t1,
            /* 2^32 times the square root of the first 8 primes 2..19 */
            h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
            h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19,
            w00, w01, w02, w03, w04, w05, w06, w07, w08, w09, w10, w11, w12, w13, w14, w15,
            w16, w17, w18, w19, w20, w21, w22, w23, w24, w25, w26, w27, w28, w29, w30, w31,
            w32, w33, w34, w35, w36, w37, w38, w39, w40, w41, w42, w43, w44, w45, w46, w47,
            w48, w49, w50, w51, w52, w53, w54, w55, w56, w57, w58, w59, w60, w61, w62, w63,
            u = 0;
        /* Compress message in 512-bit chunks. */
        while (u < chunks) {
            a = h0; b = h1; c = h2; d = h3; e = h4; f = h5; g = h6; h = h7;

            /* Round 1. */
            w00 = x[u++];
            t0 = w00 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x428a2f98) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                
            
            /* Round 2. */
            w01 = x[u++];
            t0 = w01 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x71374491) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            /* Round 3. */
            w02 = x[u++];
            t0 = w02 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xb5c0fbcf) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w03 = x[u++];
            t0 = w03 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xe9b5dba5) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w04 = x[u++];
            t0 = w04 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x3956c25b) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w05 = x[u++];
            t0 = w05 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x59f111f1) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w06 = x[u++];
            t0 = w06 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x923f82a4) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w07 = x[u++];
            t0 = w07 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xab1c5ed5) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w08 = x[u++];
            t0 = w08 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xd807aa98) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w09 = x[u++];
            t0 = w09 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x12835b01) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w10 = x[u++];
            t0 = w10 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x243185be) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w11 = x[u++];
            t0 = w11 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x550c7dc3) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w12 = x[u++];
            t0 = w12 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x72be5d74) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w13 = x[u++];
            t0 = w13 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x80deb1fe) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w14 = x[u++];
            t0 = w14 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x9bdc06a7) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w15 = x[u++];
            t0 = w15 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xc19bf174) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w16 = w00 + w09 + ((w01 >>> 7 | w01 << 25) ^ (w01 >>> 18 | w01 << 14) ^ w01 >>> 3)
                + ((w14 >>> 17 | w14 << 15) ^ (w14 >>> 19 | w14 << 13) ^ w14 >>> 10);
            t0 = w16 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xe49b69c1) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w17 = w01 + w10 + ((w02 >>> 7 | w02 << 25) ^ (w02 >>> 18 | w02 << 14) ^ w02 >>> 3)
                + ((w15 >>> 17 | w15 << 15) ^ (w15 >>> 19 | w15 << 13) ^ w15 >>> 10);
            t0 = w17 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xefbe4786) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w18 = w02 + w11 + ((w03 >>> 7 | w03 << 25) ^ (w03 >>> 18 | w03 << 14) ^ w03 >>> 3)
                + ((w16 >>> 17 | w16 << 15) ^ (w16 >>> 19 | w16 << 13) ^ w16 >>> 10);
            t0 = w18 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x0fc19dc6) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w19 = w03 + w12 + ((w04 >>> 7 | w04 << 25) ^ (w04 >>> 18 | w04 << 14) ^ w04 >>> 3)
                + ((w17 >>> 17 | w17 << 15) ^ (w17 >>> 19 | w17 << 13) ^ w17 >>> 10);
            t0 = w19 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x240ca1cc) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w20 = w04 + w13 + ((w05 >>> 7 | w05 << 25) ^ (w05 >>> 18 | w05 << 14) ^ w05 >>> 3)
                + ((w18 >>> 17 | w18 << 15) ^ (w18 >>> 19 | w18 << 13) ^ w18 >>> 10);
            t0 = w20 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x2de92c6f) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w21 = w05 + w14 + ((w06 >>> 7 | w06 << 25) ^ (w06 >>> 18 | w06 << 14) ^ w06 >>> 3)
                + ((w19 >>> 17 | w19 << 15) ^ (w19 >>> 19 | w19 << 13) ^ w19 >>> 10);
            t0 = w21 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x4a7484aa) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w22 = w06 + w15 + ((w07 >>> 7 | w07 << 25) ^ (w07 >>> 18 | w07 << 14) ^ w07 >>> 3)
                + ((w20 >>> 17 | w20 << 15) ^ (w20 >>> 19 | w20 << 13) ^ w20 >>> 10);
            t0 = w22 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x5cb0a9dc) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w23 = w07 + w16 + ((w08 >>> 7 | w08 << 25) ^ (w08 >>> 18 | w08 << 14) ^ w08 >>> 3)
                + ((w21 >>> 17 | w21 << 15) ^ (w21 >>> 19 | w21 << 13) ^ w21 >>> 10);
            t0 = w23 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x76f988da) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w24 = w08 + w17 + ((w09 >>> 7 | w09 << 25) ^ (w09 >>> 18 | w09 << 14) ^ w09 >>> 3)
                + ((w22 >>> 17 | w22 << 15) ^ (w22 >>> 19 | w22 << 13) ^ w22 >>> 10);
            t0 = w24 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x983e5152) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w25 = w09 + w18 + ((w10 >>> 7 | w10 << 25) ^ (w10 >>> 18 | w10 << 14) ^ w10 >>> 3)
                + ((w23 >>> 17 | w23 << 15) ^ (w23 >>> 19 | w23 << 13) ^ w23 >>> 10);
            t0 = w25 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xa831c66d) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w26 = w10 + w19 + ((w11 >>> 7 | w11 << 25) ^ (w11 >>> 18 | w11 << 14) ^ w11 >>> 3)
                + ((w24 >>> 17 | w24 << 15) ^ (w24 >>> 19 | w24 << 13) ^ w24 >>> 10);
            t0 = w26 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xb00327c8) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w27 = w11 + w20 + ((w12 >>> 7 | w12 << 25) ^ (w12 >>> 18 | w12 << 14) ^ w12 >>> 3)
                + ((w25 >>> 17 | w25 << 15) ^ (w25 >>> 19 | w25 << 13) ^ w25 >>> 10);
            t0 = w27 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xbf597fc7) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w28 = w12 + w21 + ((w13 >>> 7 | w13 << 25) ^ (w13 >>> 18 | w13 << 14) ^ w13 >>> 3)
                + ((w26 >>> 17 | w26 << 15) ^ (w26 >>> 19 | w26 << 13) ^ w26 >>> 10);
            t0 = w28 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xc6e00bf3) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w29 = w13 + w22 + ((w14 >>> 7 | w14 << 25) ^ (w14 >>> 18 | w14 << 14) ^ w14 >>> 3)
                + ((w27 >>> 17 | w27 << 15) ^ (w27 >>> 19 | w27 << 13) ^ w27 >>> 10);
            t0 = w29 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xd5a79147) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w30 = w14 + w23 + ((w15 >>> 7 | w15 << 25) ^ (w15 >>> 18 | w15 << 14) ^ w15 >>> 3)
                + ((w28 >>> 17 | w28 << 15) ^ (w28 >>> 19 | w28 << 13) ^ w28 >>> 10);
            t0 = w30 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x06ca6351) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w31 = w15 + w24 + ((w16 >>> 7 | w16 << 25) ^ (w16 >>> 18 | w16 << 14) ^ w16 >>> 3)
                + ((w29 >>> 17 | w29 << 15) ^ (w29 >>> 19 | w29 << 13) ^ w29 >>> 10);
            t0 = w31 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x14292967) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w32 = w16 + w25 + ((w17 >>> 7 | w17 << 25) ^ (w17 >>> 18 | w17 << 14) ^ w17 >>> 3)
                + ((w30 >>> 17 | w30 << 15) ^ (w30 >>> 19 | w30 << 13) ^ w30 >>> 10);
            t0 = w32 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x27b70a85) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w33 = w17 + w26 + ((w18 >>> 7 | w18 << 25) ^ (w18 >>> 18 | w18 << 14) ^ w18 >>> 3)
                + ((w31 >>> 17 | w31 << 15) ^ (w31 >>> 19 | w31 << 13) ^ w31 >>> 10);
            t0 = w33 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x2e1b2138) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w34 = w18 + w27 + ((w19 >>> 7 | w19 << 25) ^ (w19 >>> 18 | w19 << 14) ^ w19 >>> 3)
                + ((w32 >>> 17 | w32 << 15) ^ (w32 >>> 19 | w32 << 13) ^ w32 >>> 10);
            t0 = w34 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x4d2c6dfc) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w35 = w19 + w28 + ((w20 >>> 7 | w20 << 25) ^ (w20 >>> 18 | w20 << 14) ^ w20 >>> 3)
                + ((w33 >>> 17 | w33 << 15) ^ (w33 >>> 19 | w33 << 13) ^ w33 >>> 10);
            t0 = w35 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x53380d13) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w36 = w20 + w29 + ((w21 >>> 7 | w21 << 25) ^ (w21 >>> 18 | w21 << 14) ^ w21 >>> 3)
                + ((w34 >>> 17 | w34 << 15) ^ (w34 >>> 19 | w34 << 13) ^ w34 >>> 10);
            t0 = w36 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x650a7354) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w37 = w21 + w30 + ((w22 >>> 7 | w22 << 25) ^ (w22 >>> 18 | w22 << 14) ^ w22 >>> 3)
                + ((w35 >>> 17 | w35 << 15) ^ (w35 >>> 19 | w35 << 13) ^ w35 >>> 10);
            t0 = w37 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x766a0abb) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w38 = w22 + w31 + ((w23 >>> 7 | w23 << 25) ^ (w23 >>> 18 | w23 << 14) ^ w23 >>> 3)
                + ((w36 >>> 17 | w36 << 15) ^ (w36 >>> 19 | w36 << 13) ^ w36 >>> 10);
            t0 = w38 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x81c2c92e) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w39 = w23 + w32 + ((w24 >>> 7 | w24 << 25) ^ (w24 >>> 18 | w24 << 14) ^ w24 >>> 3)
                + ((w37 >>> 17 | w37 << 15) ^ (w37 >>> 19 | w37 << 13) ^ w37 >>> 10);
            t0 = w39 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x92722c85) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w40 = w24 + w33 + ((w25 >>> 7 | w25 << 25) ^ (w25 >>> 18 | w25 << 14) ^ w25 >>> 3)
                + ((w38 >>> 17 | w38 << 15) ^ (w38 >>> 19 | w38 << 13) ^ w38 >>> 10);
            t0 = w40 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xa2bfe8a1) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w41 = w25 + w34 + ((w26 >>> 7 | w26 << 25) ^ (w26 >>> 18 | w26 << 14) ^ w26 >>> 3)
                + ((w39 >>> 17 | w39 << 15) ^ (w39 >>> 19 | w39 << 13) ^ w39 >>> 10);
            t0 = w41 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xa81a664b) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w42 = w26 + w35 + ((w27 >>> 7 | w27 << 25) ^ (w27 >>> 18 | w27 << 14) ^ w27 >>> 3)
                + ((w40 >>> 17 | w40 << 15) ^ (w40 >>> 19 | w40 << 13) ^ w40 >>> 10);
            t0 = w42 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xc24b8b70) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w43 = w27 + w36 + ((w28 >>> 7 | w28 << 25) ^ (w28 >>> 18 | w28 << 14) ^ w28 >>> 3)
                + ((w41 >>> 17 | w41 << 15) ^ (w41 >>> 19 | w41 << 13) ^ w41 >>> 10);
            t0 = w43 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xc76c51a3) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w44 = w28 + w37 + ((w29 >>> 7 | w29 << 25) ^ (w29 >>> 18 | w29 << 14) ^ w29 >>> 3)
                + ((w42 >>> 17 | w42 << 15) ^ (w42 >>> 19 | w42 << 13) ^ w42 >>> 10);
            t0 = w44 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xd192e819) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w45 = w29 + w38 + ((w30 >>> 7 | w30 << 25) ^ (w30 >>> 18 | w30 << 14) ^ w30 >>> 3)
                + ((w43 >>> 17 | w43 << 15) ^ (w43 >>> 19 | w43 << 13) ^ w43 >>> 10);
            t0 = w45 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xd6990624) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w46 = w30 + w39 + ((w31 >>> 7 | w31 << 25) ^ (w31 >>> 18 | w31 << 14) ^ w31 >>> 3)
                + ((w44 >>> 17 | w44 << 15) ^ (w44 >>> 19 | w44 << 13) ^ w44 >>> 10);
            t0 = w46 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xf40e3585) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w47 = w31 + w40 + ((w32 >>> 7 | w32 << 25) ^ (w32 >>> 18 | w32 << 14) ^ w32 >>> 3)
                + ((w45 >>> 17 | w45 << 15) ^ (w45 >>> 19 | w45 << 13) ^ w45 >>> 10);
            t0 = w47 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x106aa070) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w48 = w32 + w41 + ((w33 >>> 7 | w33 << 25) ^ (w33 >>> 18 | w33 << 14) ^ w33 >>> 3)
                + ((w46 >>> 17 | w46 << 15) ^ (w46 >>> 19 | w46 << 13) ^ w46 >>> 10);
            t0 = w48 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x19a4c116) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w49 = w33 + w42 + ((w34 >>> 7 | w34 << 25) ^ (w34 >>> 18 | w34 << 14) ^ w34 >>> 3)
                + ((w47 >>> 17 | w47 << 15) ^ (w47 >>> 19 | w47 << 13) ^ w47 >>> 10);
            t0 = w49 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x1e376c08) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w50 = w34 + w43 + ((w35 >>> 7 | w35 << 25) ^ (w35 >>> 18 | w35 << 14) ^ w35 >>> 3)
                + ((w48 >>> 17 | w48 << 15) ^ (w48 >>> 19 | w48 << 13) ^ w48 >>> 10);
            t0 = w50 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x2748774c) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w51 = w35 + w44 + ((w36 >>> 7 | w36 << 25) ^ (w36 >>> 18 | w36 << 14) ^ w36 >>> 3)
                + ((w49 >>> 17 | w49 << 15) ^ (w49 >>> 19 | w49 << 13) ^ w49 >>> 10);
            t0 = w51 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x34b0bcb5) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w52 = w36 + w45 + ((w37 >>> 7 | w37 << 25) ^ (w37 >>> 18 | w37 << 14) ^ w37 >>> 3)
                + ((w50 >>> 17 | w50 << 15) ^ (w50 >>> 19 | w50 << 13) ^ w50 >>> 10);
            t0 = w52 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x391c0cb3) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w53 = w37 + w46 + ((w38 >>> 7 | w38 << 25) ^ (w38 >>> 18 | w38 << 14) ^ w38 >>> 3)
                + ((w51 >>> 17 | w51 << 15) ^ (w51 >>> 19 | w51 << 13) ^ w51 >>> 10);
            t0 = w53 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x4ed8aa4a) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w54 = w38 + w47 + ((w39 >>> 7 | w39 << 25) ^ (w39 >>> 18 | w39 << 14) ^ w39 >>> 3)
                + ((w52 >>> 17 | w52 << 15) ^ (w52 >>> 19 | w52 << 13) ^ w52 >>> 10);
            t0 = w54 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x5b9cca4f) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w55 = w39 + w48 + ((w40 >>> 7 | w40 << 25) ^ (w40 >>> 18 | w40 << 14) ^ w40 >>> 3)
                + ((w53 >>> 17 | w53 << 15) ^ (w53 >>> 19 | w53 << 13) ^ w53 >>> 10);
            t0 = w55 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x682e6ff3) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w56 = w40 + w49 + ((w41 >>> 7 | w41 << 25) ^ (w41 >>> 18 | w41 << 14) ^ w41 >>> 3)
                + ((w54 >>> 17 | w54 << 15) ^ (w54 >>> 19 | w54 << 13) ^ w54 >>> 10);
            t0 = w56 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x748f82ee) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w57 = w41 + w50 + ((w42 >>> 7 | w42 << 25) ^ (w42 >>> 18 | w42 << 14) ^ w42 >>> 3)
                + ((w55 >>> 17 | w55 << 15) ^ (w55 >>> 19 | w55 << 13) ^ w55 >>> 10);
            t0 = w57 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x78a5636f) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w58 = w42 + w51 + ((w43 >>> 7 | w43 << 25) ^ (w43 >>> 18 | w43 << 14) ^ w43 >>> 3)
                + ((w56 >>> 17 | w56 << 15) ^ (w56 >>> 19 | w56 << 13) ^ w56 >>> 10);
            t0 = w58 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x84c87814) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w59 = w43 + w52 + ((w44 >>> 7 | w44 << 25) ^ (w44 >>> 18 | w44 << 14) ^ w44 >>> 3)
                + ((w57 >>> 17 | w57 << 15) ^ (w57 >>> 19 | w57 << 13) ^ w57 >>> 10);
            t0 = w59 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x8cc70208) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w60 = w44 + w53 + ((w45 >>> 7 | w45 << 25) ^ (w45 >>> 18 | w45 << 14) ^ w45 >>> 3)
                + ((w58 >>> 17 | w58 << 15) ^ (w58 >>> 19 | w58 << 13) ^ w58 >>> 10);
            t0 = w60 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0x90befffa) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            w61 = w45 + w54 + ((w46 >>> 7 | w46 << 25) ^ (w46 >>> 18 | w46 << 14) ^ w46 >>> 3)
                + ((w59 >>> 17 | w59 << 15) ^ (w59 >>> 19 | w59 << 13) ^ w59 >>> 10);
            t0 = w61 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xa4506ceb) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;             

            /* Round 63. */
            w62 = w46 + w55 + ((w47 >>> 7 | w47 << 25) ^ (w47 >>> 18 | w47 << 14) ^ w47 >>> 3)
                + ((w60 >>> 17 | w60 << 15) ^ (w60 >>> 19 | w60 << 13) ^ w60 >>> 10);
            t0 = w62 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xbef9a3f7) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;                

            /* Round 64. */
            w63 = w47 + w56 + ((w48 >>> 7 | w48 << 25) ^ (w48 >>> 18 | w48 << 14) ^ w48 >>> 3)
                + ((w61 >>> 17 | w61 << 15) ^ (w61 >>> 19 | w61 << 13) ^ w61 >>> 10);
            t0 = w63 + ((h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + (g ^ e & (f ^ g)) + 0xc67178f2) << 0);
            t1 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & b ^ c & (a ^ b));
            h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;            

            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
        }

        /* This will be transformed automagically into the desired output format. */
        return [h0, h1, h2, h3, h4, h5, h6, h7];
    }

};