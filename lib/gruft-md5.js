/*!
 *  gruft-md5 module Version 0.0.8-2009xxyy Copyright (c) 2009 Nikola Klaric.
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
 *  The MD5 algorithm was designed by Ronald Rivest.
 */

/**
 * @namespace gruft.*
 */
var gruft; if (typeof(gruft) !== typeof(Object.prototype)) { gruft = {}; }

/**
 * 
 */
gruft.MD5 = function () {
    if (typeof(gruft.common) !== typeof(gruft)) {
        throw new Error("module <gruft.common> not found");
    }
    gruft.common.reflect(this, gruft.__MD5__, arguments);
    this.selftest();
};

/**
 *
 */
gruft.__MD5__ = function () {
    if (this instanceof gruft.__MD5__) {
        this.__init__.apply(this, arguments);
    }
};

/**
 *
 */
gruft.__MD5__.prototype = {

    __name__   : "gruft.MD5",
    __repr__   : "MD5",
    __author__ : "Nikola Klaric",
    __version__: "0.0.8",

    /**
     * Initialize this instance of <gruft.__MD5__> and set up internal objects.
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

        var digest = this.__digest__, gc = gruft.common, error = "MD5 digest of test vector %1 is erroneous",
            failUnlessEqual = gc.failUnlessEqual, getTestvector = gc.getTestvector, clipString = gc.clipString;

        /* Basic. */
        failUnlessEqual(
            digest(""),
            "d41d8cd98f00b204e9800998ecf8427e",
            error, "'' (empty string)");
        failUnlessEqual(
            digest(getTestvector("digest-base64")),
            "08e39f7e8b0b62394f040746a17ca1f6",
            error, "{digest-base64}");

        /* 24 chars between 0x00 .. 0x80 .. 0xff. */
        failUnlessEqual(
            digest(getTestvector("digest-span-utf8")),
            "34c4e74c0da5f130dd6f82a30853c996",
            error, "{digest-span-utf8}");

        /* 24 chars between 0x0000 .. 0x8000 .. 0xffff. */
        failUnlessEqual(
            digest(getTestvector("digest-span-utf16")),
            "d086073d4a685c6d9a10edf684d591bc",
            error, "{digest-span-utf16} (implicitly clipped to byte-sized characters)");
        failUnlessEqual(
            digest(getTestvector("digest-span-utf16")), 
            digest(clipString(getTestvector("digest-span-utf16"))),
            error, "{digest-span-utf16} (explicitly clipped to byte-sized characters)");

        /* 1024 zeros. */
        failUnlessEqual(
            digest(getTestvector("digest-1024x0")),
            "0f343b0931126a20f133d67c2b018a3b",
            error, "{digest-1024x0}");

        /* 1031 randomly selected (but stable) chars. */
        failUnlessEqual(
            digest(getTestvector("digest-random")),
            "1407ed3b268f077aca21047b335c0133",
            error, "{digest-random}");

        /* Format to byte sequence. */
        failUnlessEqual(
            digest({message:"MD5", format:"byteseq"}),
            [0x7f, 0x13, 0x8a, 0x09, 0x16, 0x9b, 0x25, 0x0e, 0x9d, 0xcb, 0x37, 0x81, 0x40, 0x90, 0x73, 0x78],
            error, "'MD5' (formatted to byte sequence)");

        /* Format to base64. */
        failUnlessEqual(
            digest({message:"ABCDEFGHIJ"}),
            "e86410fa2d6e2634fd8ac5f4b3afe7f3",
            error, "'ABCDEFGHIJ' (formatted to hex string)");
        failUnlessEqual(
            digest({message:"ABCDEFGHIJ", format:"base64"}),
            "6GQQ+i1uJjT9isX0s6/n8w==",
            error, "'ABCDEFGHIJ' (formatted to base64)");
        failUnlessEqual(
            digest("ABCDEFGHIJ", {format:"base64_safe"}),
            "6GQQ*i1uJjT9isX0s6-n8w",
            error, "'ABCDEFGHIJ' (formatted to base64, URL-safe)");
    },

    /**
     * Compress message to MD5 digest in pure Javascript.
     *
     * @param {String} message The string to compress. 
     * @return {Array} MD5 digest as a 4-tuple of 32-bit words.
     */
    __digest__: function (message) {
        var bits = message.length * 8, chunks = 16 + ((bits + 64 >>> 9) << 4) - 1, padded = 16 + chunks - 1,
            x = new Array(padded), n = -1;
        while (++n < padded) { x[n] = 0; }
        for (n = 0; n < bits; n += 8) {
            /* Clip to byte-sized characters. */
            x[n >> 5] |= (message.charCodeAt(n / 8) & 0xff) << n % 32;
        }

        /* Apply MD5 padding (big-bit-endian, little-byte-endian, left-justified). */
        x[bits >> 5] |= 0x80 << bits % 32;
        x[chunks - 1] = bits;

        var u = 0, x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15,
            a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476, e, tmpa, tmpb, tmpc, tmpd;
        /* Compress message in 512-bit chunks. */
        while (u < chunks) {
            tmpa = a; tmpb = b; tmpc = c; tmpd = d;

            x00 = x[u++]; x01 = x[u++]; x02 = x[u++]; x03 = x[u++]; x04 = x[u++]; x05 = x[u++]; x06 = x[u++]; x07 = x[u++];
            x08 = x[u++]; x09 = x[u++]; x10 = x[u++]; x11 = x[u++]; x12 = x[u++]; x13 = x[u++]; x14 = x[u++]; x15 = x[u++];

            /* Round 1. */
            e = 0xd76aa478 + x00 + a + (d ^ b & (c ^ d)); a = b + (e <<  7 | e >>> 25);
            e = 0xe8c7b756 + x01 + d + (c ^ a & (b ^ c)); d = a + (e << 12 | e >>> 20);
            e = 0x242070db + x02 + c + (b ^ d & (a ^ b)); c = d + (e << 17 | e >>> 15);
            e = 0xc1bdceee + x03 + b + (a ^ c & (d ^ a)); b = c + (e << 22 | e >>> 10);
            e = 0xf57c0faf + x04 + a + (d ^ b & (c ^ d)); a = b + (e <<  7 | e >>> 25);
            e = 0x4787c62a + x05 + d + (c ^ a & (b ^ c)); d = a + (e << 12 | e >>> 20);
            e = 0xa8304613 + x06 + c + (b ^ d & (a ^ b)); c = d + (e << 17 | e >>> 15);
            e = 0xfd469501 + x07 + b + (a ^ c & (d ^ a)); b = c + (e << 22 | e >>> 10);
            e = 0x698098d8 + x08 + a + (d ^ b & (c ^ d)); a = b + (e <<  7 | e >>> 25);
            e = 0x8b44f7af + x09 + d + (c ^ a & (b ^ c)); d = a + (e << 12 | e >>> 20);
            e = 0xffff5bb1 + x10 + c + (b ^ d & (a ^ b)); c = d + (e << 17 | e >>> 15);
            e = 0x895cd7be + x11 + b + (a ^ c & (d ^ a)); b = c + (e << 22 | e >>> 10);
            e = 0x6b901122 + x12 + a + (d ^ b & (c ^ d)); a = b + (e <<  7 | e >>> 25);
            e = 0xfd987193 + x13 + d + (c ^ a & (b ^ c)); d = a + (e << 12 | e >>> 20);
            e = 0xa679438e + x14 + c + (b ^ d & (a ^ b)); c = d + (e << 17 | e >>> 15);
            e = 0x49b40821 + x15 + b + (a ^ c & (d ^ a)); b = c + (e << 22 | e >>> 10);

            /* Round 2. */
            e = 0xf61e2562 + x01 + a + (c ^ d & (b ^ c)); a = b + (e <<  5 | e >>> 27);
            e = 0xc040b340 + x06 + d + (b ^ c & (a ^ b)); d = a + (e <<  9 | e >>> 23);
            e = 0x265e5a51 + x11 + c + (a ^ b & (d ^ a)); c = d + (e << 14 | e >>> 18);
            e = 0xe9b6c7aa + x00 + b + (d ^ a & (c ^ d)); b = c + (e << 20 | e >>> 12);
            e = 0xd62f105d + x05 + a + (c ^ d & (b ^ c)); a = b + (e <<  5 | e >>> 27);
            e = 0x02441453 + x10 + d + (b ^ c & (a ^ b)); d = a + (e <<  9 | e >>> 23);
            e = 0xd8a1e681 + x15 + c + (a ^ b & (d ^ a)); c = d + (e << 14 | e >>> 18);
            e = 0xe7d3fbc8 + x04 + b + (d ^ a & (c ^ d)); b = c + (e << 20 | e >>> 12);
            e = 0x21e1cde6 + x09 + a + (c ^ d & (b ^ c)); a = b + (e <<  5 | e >>> 27);
            e = 0xc33707d6 + x14 + d + (b ^ c & (a ^ b)); d = a + (e <<  9 | e >>> 23);
            e = 0xf4d50d87 + x03 + c + (a ^ b & (d ^ a)); c = d + (e << 14 | e >>> 18);
            e = 0x455a14ed + x08 + b + (d ^ a & (c ^ d)); b = c + (e << 20 | e >>> 12);
            e = 0xa9e3e905 + x13 + a + (c ^ d & (b ^ c)); a = b + (e <<  5 | e >>> 27);
            e = 0xfcefa3f8 + x02 + d + (b ^ c & (a ^ b)); d = a + (e <<  9 | e >>> 23);
            e = 0x676f02d9 + x07 + c + (a ^ b & (d ^ a)); c = d + (e << 14 | e >>> 18);
            e = 0x8d2a4c8a + x12 + b + (d ^ a & (c ^ d)); b = c + (e << 20 | e >>> 12);

            /* Round 3. */
            e = 0xfffa3942 + x05 + a + (b ^ c ^ d);       a = b + (e <<  4 | e >>> 28);
            e = 0x8771f681 + x08 + d + (a ^ b ^ c);       d = a + (e << 11 | e >>> 21);
            e = 0x6d9d6122 + x11 + c + (d ^ a ^ b);       c = d + (e << 16 | e >>> 16);
            e = 0xfde5380c + x14 + b + (c ^ d ^ a);       b = c + (e << 23 | e >>>  9);
            e = 0xa4beea44 + x01 + a + (b ^ c ^ d);       a = b + (e <<  4 | e >>> 28);
            e = 0x4bdecfa9 + x04 + d + (a ^ b ^ c);       d = a + (e << 11 | e >>> 21);
            e = 0xf6bb4b60 + x07 + c + (d ^ a ^ b);       c = d + (e << 16 | e >>> 16);
            e = 0xbebfbc70 + x10 + b + (c ^ d ^ a);       b = c + (e << 23 | e >>>  9);
            e = 0x289b7ec6 + x13 + a + (b ^ c ^ d);       a = b + (e <<  4 | e >>> 28);
            e = 0xeaa127fa + x00 + d + (a ^ b ^ c);       d = a + (e << 11 | e >>> 21);
            e = 0xd4ef3085 + x03 + c + (d ^ a ^ b);       c = d + (e << 16 | e >>> 16);
            e = 0x04881d05 + x06 + b + (c ^ d ^ a);       b = c + (e << 23 | e >>>  9);
            e = 0xd9d4d039 + x09 + a + (b ^ c ^ d);       a = b + (e <<  4 | e >>> 28);
            e = 0xe6db99e5 + x12 + d + (a ^ b ^ c);       d = a + (e << 11 | e >>> 21);
            e = 0x1fa27cf8 + x15 + c + (d ^ a ^ b);       c = d + (e << 16 | e >>> 16);
            e = 0xc4ac5665 + x02 + b + (c ^ d ^ a);       b = c + (e << 23 | e >>>  9);

            /* Round 4. */
            e = 0xf4292244 + x00 + a + (c ^ (b | ~d));    a = b + (e <<  6 | e >>> 26);
            e = 0x432aff97 + x07 + d + (b ^ (a | ~c));    d = a + (e << 10 | e >>> 22);
            e = 0xab9423a7 + x14 + c + (a ^ (d | ~b));    c = d + (e << 15 | e >>> 17);
            e = 0xfc93a039 + x05 + b + (d ^ (c | ~a));    b = c + (e << 21 | e >>> 11);
            e = 0x655b59c3 + x12 + a + (c ^ (b | ~d));    a = b + (e <<  6 | e >>> 26);
            e = 0x8f0ccc92 + x03 + d + (b ^ (a | ~c));    d = a + (e << 10 | e >>> 22);
            e = 0xffeff47d + x10 + c + (a ^ (d | ~b));    c = d + (e << 15 | e >>> 17);
            e = 0x85845dd1 + x01 + b + (d ^ (c | ~a));    b = c + (e << 21 | e >>> 11);
            e = 0x6fa87e4f + x08 + a + (c ^ (b | ~d));    a = b + (e <<  6 | e >>> 26);
            e = 0xfe2ce6e0 + x15 + d + (b ^ (a | ~c));    d = a + (e << 10 | e >>> 22);
            e = 0xa3014314 + x06 + c + (a ^ (d | ~b));    c = d + (e << 15 | e >>> 17);
            e = 0x4e0811a1 + x13 + b + (d ^ (c | ~a));    b = c + (e << 21 | e >>> 11);
            e = 0xf7537e82 + x04 + a + (c ^ (b | ~d));    a = b + (e <<  6 | e >>> 26);
            e = 0xbd3af235 + x11 + d + (b ^ (a | ~c));    d = a + (e << 10 | e >>> 22);
            e = 0x2ad7d2bb + x02 + c + (a ^ (d | ~b));    c = d + (e << 15 | e >>> 17);
            e = 0xeb86d391 + x09 + b + (d ^ (c | ~a));    b = c + (e << 21 | e >>> 11);

            /* Wrap to 32-bit unsigned modulo 2^32. */
            a = (a + tmpa) << 0; b = (b + tmpb) << 0; c = (c + tmpc) << 0; d = (d + tmpd) << 0;
        }

        /* This will be transformed automagically into the desired output format. */
        return [a, b, c, d];
    }

};
