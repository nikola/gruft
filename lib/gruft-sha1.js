/**
 *  gruft-sha1 module Version 0.0.8-2007xxyy Copyright (c) 2007 Nikola Klaric.
 *
 *  Licensed under the Open Software License 3.0 (OSL 3.0).
 *
 *  For the full license text see the enclosed LICENSE.TXT, or go to:
 *  http://opensource.org/licenses/osl-3.0.php
 *
 *  This software is part of the gruft cryptography library project:
 *  http://sourceforge.net/projects/gruft
 *
 *  If you are using this library for commercial purposes, we encourage you
 *  to purchase a commercial license. Please visit the gruft project homepage
 *  at sourceforge.net for more details.
 *
 *  The SHA-1 algorithm was designed by the National Security Agency (NSA).
 */

/**
 * @namespace gruft.*
 */
var gruft; if (typeof(gruft) !== typeof(Object.prototype)) { gruft = {}; }

/**
 *
 */
gruft.SHA1 = function () {
    if (typeof(gruft.common) !== typeof(gruft)) {
        throw new Error("module <gruft.common> not found");
    }
    gruft.common.reflect(this, gruft.__SHA1__, arguments);
    this.selftest();
};

/**
 *
 */
gruft.__SHA1__ = function () {
    if (this instanceof gruft.__SHA1__) {
        this.__init__.apply(this, arguments);
    }
};

/**
 *
 */
gruft.__SHA1__.prototype = {

    __name__    : "gruft.SHA1",
    __repr__    : "SHA-1",    
    __author__  : "Nikola Klaric",
    __version__ : "0.0.8",

    /**
     * Initialize this instance of <gruft.__SHA1__> and set up internal objects.
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

        var digest = this.__digest__, gc = gruft.common, error = "SHA-1 digest of test vector %s is erroneous",
            failUnlessEqual = gc.failUnlessEqual, getTestvector = gc.getTestvector, clipString = gc.clipString;

        /* Basic. */
        failUnlessEqual(
            digest(""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            error, "'' (empty string)");
        failUnlessEqual(
            digest(getTestvector("digest-base64")),
            "1d278d3c888d1a2fa7eed622bfc02927ce4049af",
            error, "{digest-base64}");

        /* 24 chars between 0x00 .. 0x80 .. 0xff. */
        failUnlessEqual(
            digest(getTestvector("digest-span-utf8")),
            "ae2b8506e503b1e0ec3cfd276c68e018e7991301",
            error, "{digest-span-utf8}");

        /* 24 chars between 0x0000 .. 0x8000 .. 0xffff. */
        failUnlessEqual(
            digest(getTestvector("digest-span-utf16")),
            "a3a7c90044d847ad034f4c202a8a4da8cb2cd86d",
            error, "{digest-span-utf16} (implicitly clipped to byte-sized characters)");
        failUnlessEqual(
            digest(getTestvector("digest-span-utf16")), 
            digest(clipString(getTestvector("digest-span-utf16"))),
            error, "{digest-span-utf16} (explicitly clipped to byte-sized characters)");

        /* 1024 zeros. */
        failUnlessEqual(
            digest(getTestvector("digest-1024x0")),
            "60cacbf3d72e1e7834203da608037b1bf83b40e8",
            error, "{digest-1024x0}");

        /* 1031 randomly selected chars. */
        failUnlessEqual(
            digest(getTestvector("digest-random")),
            "5370c98b9571ec854d7523340f6e16034c12ae98",
            error, "{digest-random}");

        /* Format to byte sequence. */
        failUnlessEqual(
            digest({message:"SHA-1", format:"byteseq"}),
            [0xc5, 0x71, 0xb8, 0x65, 0x49, 0xe4, 0x9b, 0xf2, 0x23, 0xcf,
             0x64, 0x83, 0x88, 0xc4, 0x62, 0x88, 0xc2, 0x24, 0x1b, 0x5a],
             error, "'SHA-1' (formatted to byte sequence)");

        /* Format to base64. */
        failUnlessEqual(
            digest({message:"ABCDE"}),
            "7be07aaf460d593a323d0db33da05b64bfdcb3a5",
            error, "'ABCDE' (formatted to hex string)");
        failUnlessEqual(
            digest({message:"ABCDE", format:"base64"}),
            "e+B6r0YNWToyPQ2zPaBbZL/cs6U=",
            error, "'ABCDE' (formatted to base64)");
        failUnlessEqual(
            digest("ABCDE", {format:"base64_safe"}),
            "e*B6r0YNWToyPQ2zPaBbZL-cs6U",
            error, "'ABCDE' (formatted to base64, URL-safe)");
    },

    /**
     * Compress message to SHA-1 digest in pure Javascript.
     * 
     * @param {String} message The string to compress. 
     * @return {Array} SHA-1 digest as a 5-tuple of 32-bit words.
     */
    __digest__: function (message) {
        var bits = message.length * 8, chunks = 16 + ((bits + 64 >>> 9) << 4), padded = 16 + chunks + 64 - 1,
            x = new Array(padded), n = -1;
        while (++n < padded) { x[n] = 0; }
        for (n = 0; n < bits; n += 8) {
            /* Clip to byte-sized characters. */
            x[n >> 5] |= (message.charCodeAt(n / 8) & 0xff) << 24 - n % 32;
        }

        /*  Apply MD5 padding (big-bit-endian, big-byte-endian, left-justified). */
        x[bits >> 5] |= 0x80 << 24 - bits % 32;
        x[chunks - 1] = bits;

        var a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476, e = 0xc3d2e1f0, f, g, tmpa, tmpb, tmpc, tmpd, tmpe,
        // TODO: rewrite variable names to h i j ... z A ... Z _
            w00, w01, w02, w03, w04, w05, w06, w07, w08, w09, w10, w11, w12, w13, w14, w15,
            w16, w17, w18, w19, w20, w21, w22, w23, w24, w25, w26, w27, w28, w29, w30, w31,
            w32, w33, w34, w35, w36, w37, w38, w39, w40, w41, w42, w43, w44, w45, w46, w47,
            w48, w49, w50, w51, w52, w53, w54, w55, w56, w57, w58, w59, w60, w61, w62, w63,
            w64, w65, w66, w67, w68, w69, w70, w71, w72, w73, w74, w75, w76, w77, w78, w79,
            u = 0;
        /* Compress message in 512-bit chunks. */
        while (u < chunks) {
            tmpa = a; tmpb = b; tmpc = c; tmpd = d; tmpe = e;

            /* Round 1. */
            w00 = x[u++];
            f = 0x5a827999 + w00 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;

            /* Round 2. */
            w01 = x[u++];
            f = 0x5a827999 + w01 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;

            /* Round 3. */
            w02 = x[u++];
            f = 0x5a827999 + w02 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w03 = x[u++];
            f = 0x5a827999 + w03 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w04 = x[u++];
            f = 0x5a827999 + w04 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w05 = x[u++];
            f = 0x5a827999 + w05 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w06 = x[u++];
            f = 0x5a827999 + w06 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w07 = x[u++];
            f = 0x5a827999 + w07 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w08 = x[u++];
            f = 0x5a827999 + w08 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w09 = x[u++];
            f = 0x5a827999 + w09 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                                
            w10 = x[u++];
            f = 0x5a827999 + w10 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w11 = x[u++];
            f = 0x5a827999 + w11 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w12 = x[u++];
            f = 0x5a827999 + w12 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w13 = x[u++];
            f = 0x5a827999 + w13 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w14 = x[u++];
            f = 0x5a827999 + w14 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            w15 = x[u++];
            f = 0x5a827999 + w15 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w13 ^ w08 ^ w02 ^ w00; w16 = g << 1 | g >>> 31;
            f = 0x5a827999 + w16 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w14 ^ w09 ^ w03 ^ w01; w17 = g << 1 | g >>> 31;
            f = 0x5a827999 + w17 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w15 ^ w10 ^ w04 ^ w02; w18 = g << 1 | g >>> 31;
            f = 0x5a827999 + w18 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w16 ^ w11 ^ w05 ^ w03; w19 = g << 1 | g >>> 31;
            f = 0x5a827999 + w19 + e + (a << 5 | a >>> 27) + (d ^ b & (c ^ d));     e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w17 ^ w12 ^ w06 ^ w04; w20 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w20 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w18 ^ w13 ^ w07 ^ w05; w21 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w21 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w19 ^ w14 ^ w08 ^ w06; w22 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w22 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w20 ^ w15 ^ w09 ^ w07; w23 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w23 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w21 ^ w16 ^ w10 ^ w08; w24 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w24 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w22 ^ w17 ^ w11 ^ w09; w25 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w25 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w23 ^ w18 ^ w12 ^ w10; w26 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w26 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w24 ^ w19 ^ w13 ^ w11; w27 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w27 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w25 ^ w20 ^ w14 ^ w12; w28 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w28 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w26 ^ w21 ^ w15 ^ w13; w29 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w29 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w27 ^ w22 ^ w16 ^ w14; w30 = g << 1 | g >>> 31; 
            f = 0x6ed9eba1 + w30 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w28 ^ w23 ^ w17 ^ w15; w31 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w31 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w29 ^ w24 ^ w18 ^ w16; w32 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w32 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w30 ^ w25 ^ w19 ^ w17; w33 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w33 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w31 ^ w26 ^ w20 ^ w18; w34 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w34 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                             
            g = w32 ^ w27 ^ w21 ^ w19; w35 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w35 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w33 ^ w28 ^ w22 ^ w20; w36 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w36 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w34 ^ w29 ^ w23 ^ w21; w37 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w37 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w35 ^ w30 ^ w24 ^ w22; w38 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w38 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w36 ^ w31 ^ w25 ^ w23; w39 = g << 1 | g >>> 31;
            f = 0x6ed9eba1 + w39 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w37 ^ w32 ^ w26 ^ w24; w40 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w40 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w38 ^ w33 ^ w27 ^ w25; w41 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w41 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w39 ^ w34 ^ w28 ^ w26; w42 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w42 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w40 ^ w35 ^ w29 ^ w27; w43 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w43 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w41 ^ w36 ^ w30 ^ w28; w44 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w44 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w42 ^ w37 ^ w31 ^ w29; w45 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w45 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w43 ^ w38 ^ w32 ^ w30; w46 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w46 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w44 ^ w39 ^ w33 ^ w31; w47 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w47 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w45 ^ w40 ^ w34 ^ w32; w48 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w48 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w46 ^ w41 ^ w35 ^ w33; w49 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w49 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w47 ^ w42 ^ w36 ^ w34; w50 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w50 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w48 ^ w43 ^ w37 ^ w35; w51 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w51 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w49 ^ w44 ^ w38 ^ w36; w52 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w52 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w50 ^ w45 ^ w39 ^ w37; w53 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w53 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w51 ^ w46 ^ w40 ^ w38; w54 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w54 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w52 ^ w47 ^ w41 ^ w39; w55 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w55 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w53 ^ w48 ^ w42 ^ w40; w56 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w56 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w54 ^ w49 ^ w43 ^ w41; w57 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w57 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w55 ^ w50 ^ w44 ^ w42; w58 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w58 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w56 ^ w51 ^ w45 ^ w43; w59 = g << 1 | g >>> 31;
            f = 0x8f1bbcdc + w59 + e + (a << 5 | a >>> 27) + (b & c | d & (b | c)); e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w57 ^ w52 ^ w46 ^ w44; w60 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w60 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w58 ^ w53 ^ w47 ^ w45; w61 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w61 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w59 ^ w54 ^ w48 ^ w46; w62 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w62 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w60 ^ w55 ^ w49 ^ w47; w63 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w63 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w61 ^ w56 ^ w50 ^ w48; w64 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w64 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w62 ^ w57 ^ w51 ^ w49; w65 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w65 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w63 ^ w58 ^ w52 ^ w50; w66 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w66 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w64 ^ w59 ^ w53 ^ w51; w67 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w67 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w65 ^ w60 ^ w54 ^ w52; w68 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w68 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w66 ^ w61 ^ w55 ^ w53; w69 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w69 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w67 ^ w62 ^ w56 ^ w54; w70 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w70 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w68 ^ w63 ^ w57 ^ w55; w71 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w71 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w69 ^ w64 ^ w58 ^ w56; w72 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w72 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w70 ^ w65 ^ w59 ^ w57; w73 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w73 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w71 ^ w66 ^ w60 ^ w58; w74 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w74 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w72 ^ w67 ^ w61 ^ w59; w75 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w75 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w73 ^ w68 ^ w62 ^ w60; w76 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w76 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            g = w74 ^ w69 ^ w63 ^ w61; w77 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w77 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                           
            /* Round 79. */                            
            g = w75 ^ w70 ^ w64 ^ w62; w78 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w78 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;
                            
            /* Round 80. */                            
            g = w76 ^ w71 ^ w65 ^ w63; w79 = g << 1 | g >>> 31;
            f = 0xca62c1d6 + w79 + e + (a << 5 | a >>> 27) + (b ^ c ^ d);           e = d; d = c; c = b << 30 | b >>> 2; b = a; a = f;

            a += tmpa; b += tmpb; c += tmpc; d += tmpd; e += tmpe;
        }

        /* This will be transformed automagically into the desired output format. */
        return [a, b, c, d, e];
    }

};
