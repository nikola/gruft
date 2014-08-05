/*!
 * gruft-tiger192 module Version 0.2.0
 * Copyright 2009-2014, Nikola Klaric.
 *
 * https://github.com/nikola/gruft
 *
 * Licensed under the MIT License.
 *
 * The Tiger/192 algorithm was designed by Ross Anderson and Eli Biham.  
 */

/**
 * @namespace gruft.*
 */
;var gruft; if (typeof gruft !== typeof {}) { gruft = {}; }

/**
 * Factory for producing safe instances.
 */
gruft.Tiger192 = function () {
    if (typeof gruft.common === typeof gruft && typeof gruft.common.reflect === typeof gruft.Tiger192) {
        gruft.common.reflect(this, gruft.__Tiger192__, arguments);
    } else {
        throw "Module <gruft.common> not found";    
    }
};

/**
 * Implementation of TIGER/192 digest function.
 */
gruft.__Tiger192__ = function () { }; gruft.__Tiger192__.prototype = {

    __module__  : "gruft.Tiger192",
    __author__  : "Nikola Klaric",
    __version__ : "0.2.0",

    /**
     * Initialize this instance of <gruft.__Tiger192__> and set up internal objects.
     */
    __init__: function () { 
        /* Transform pre-computed S-boxes from base 91 to base 256. */
        for (var field in this) {
            if (/^_T\d_\d$/.test(field)) {
                this[field] = gruft.common.transformBox(this[field]);
            }
        }
    },

    /**
     * Perform self-test using discrete test vectors.
     * 
     * @exception {gruft.IntegrityError} 
     *          Raised if __digest__() is not a valid function.
     * @exception {gruft.AssertionError} 
     *          Raised if a test vector fails.
     */
    selftest: function () {
        if (typeof this.__digest__ !== typeof this.selftest) {
            throw gruft.IntegrityError("<%s.__digest__> is not callable", this.__module__, "gruft-tiger192.js");
        }

        var digest = this.__digest__, gc = gruft.common, error = "TIGER/192 digest of test vector %s is erroneous",
            getTestvector = gc.getTestvector, clipString = gc.clipString,
            failUnlessEqual = gc.bind(gc.failUnlessEqual, gc, "gruft-tiger192.js");

        /* Basic. See also: http://www.cs.technion.ac.il/~biham/Reports/Tiger/test-vectors-nessie-format.dat */
        failUnlessEqual(
            digest(""),
            "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
            error, "(empty string)");
        failUnlessEqual(
            digest(getTestvector("digest-base64")),
            "55faa30905529d5e6badf5781809dedbca650760be850d0c",
            error, "{digest-base64}");

        /* 24 chars between 0x00 .. 0x80 .. 0xff. */
        failUnlessEqual(
            digest(getTestvector("digest-span-utf8")),
            "8f8c57f5e8bfcfa5094002aa8a208ed8e0a285611ebdde4b",
            error, "{digest-span-utf8}");

        /* 1024 zeros. */
        failUnlessEqual(
            digest(getTestvector("digest-1024x0")),
            "1fa973bdd2018e89887cad6274c38f12916c6ac43bd2ea5b",
            error, "{digest-1024x0}");

        /* 1031 randomly selected (but stable) chars. */
        failUnlessEqual(
            digest(getTestvector("digest-random")),
            "f72d942817a0c8e222033f7684cd1158d5f0aa666b88e808",
            error, "{digest-random}");

        /* Format to byte sequence. */
        failUnlessEqual(
            digest({message:"Tiger", format:"byteseq", order:"big"}),
            [0x9f, 0x00, 0xf5, 0x99, 0x07, 0x23, 0x00, 0xdd, 0x27, 0x6a, 0xbb, 0x38,
             0xc8, 0xeb, 0x6d, 0xec, 0x37, 0x79, 0x0c, 0x11, 0x6f, 0x9d, 0x2b, 0xdf],
             error, "'Tiger' (formatted to byte sequence)");

        /* Format to base64. */
        failUnlessEqual(
            digest({message:"ABCDEFGHIJKLMNOPQRS"}),
            "381f6b8035a54a77f0827fc11d2b2f090d50024f90b14bb6",
            error, "'ABCDEFGHIJKLMNOPQRS' (formatted to hex string)");
        failUnlessEqual(
            digest({message:"ABCDEFGHIJKLMNOPQRS", format:"base64"}),
            "OB9rgDWlSnfwgn/BHSsvCQ1QAk+QsUu2",
            error, "'ABCDEFGHIJKLMNOPQRS' (formatted to base64)");
        failUnlessEqual(
            digest({message:"ABCDEFGHIJKLMNOPQRS", format:"base64_safe"}),
            // "OB9rgDWlSnfwgn-BHSsvCQ1QAk*QsUu2",
            "OB9rgDWlSnfwgn_BHSsvCQ1QAk-QsUu2",
            error, "'ABCDEFGHIJKLMNOPQRS' (formatted to base64, URL-safe)");

        /* Additonal vectors from: http://www.cs.technion.ac.il/~biham/Reports/Tiger/testresults.html */
        failUnlessEqual(
            digest("Tiger", {order:"big"}),
            "9f00f599072300dd276abb38c8eb6dec37790c116f9d2bdf",
            error, "'Tiger' (big-endian)");
        var vector = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, "
            + "proceedings of Fast Software Encryption 3, Cambridge.";
        failUnlessEqual(
            digest(vector, {order:"big"}),
            "ebf591d5afa655ce7f22894ff87f54ac89c811b6b0da3193",
            error, "'" + vector + "' (big-endian)");
        vector = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
        failUnlessEqual(
            digest(vector, {order:"big"}),
            "87fb2a9083851cf7470d2cf810e6df9eb586445034a5a386",
            error, "'" + vector + "' (big-endian)");
        vector = "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789";
        failUnlessEqual(
            digest(vector, {order:"big"}),
            "467db80863ebce488df1cd1261655de957896565975f9197",
            error, "'" + vector + "' (big-endian)");
        
        return true;
    },

    /**
     * Compress message to Tiger/192 digest.
     * 
     * @param {String} message 
     *          The string to compress. 
     * @param {Object} options 
     *          Destination format options.
     * 
     * @return {Array} 
     *          Tiger/192 digest as a 6-tuple of 32-bit words. 
     */
    __digest__: function (message, options) {
        var len = message.length, bits = len * 8, words = (len + 1) % 64,
            zeros = ((!len || len % 64) ? (!!words) ? (64 - words < 8) ?  64 + 1 - words : 1 - words : 1 : 0) + 64 - 8 - 1,
            padded = len + zeros + 8 + 1;

        /* Apply MD4 padding (little-bit-endian, little-byte-endian, right-justified). */
        var sfc = String.fromCharCode, padding = [sfc(1)], z = -1;
        while (++z < zeros) { 
            padding.push(sfc(0)); 
        }
        padding.push(sfc(bits & 0xff, bits >> 8 & 0xff, bits >> 16 & 0xff, bits >> 24 & 0xff, 0, 0, 0, 0));
        message += padding.join("");

        /* Compress message. */
        var x0_0, x0_1, x1_0, x1_1, x2_0, x2_1, x3_0, x3_1, x4_0, x4_1, x5_0, x5_1, x6_0, x6_1, x7_0, x7_1,
            T1_0 = this._T1_0, T1_1 = this._T1_1, T2_0 = this._T2_0, T2_1 = this._T2_1,
            T3_0 = this._T3_0, T3_1 = this._T3_1, T4_0 = this._T4_0, T4_1 = this._T4_1,
            s0_1 = 0x01234567, s0_0 = 0x89abcdef, s1_1 = 0xfedcba98, s1_0 = 0x76543210, s2_1 = 0xf096a5b4, s2_0 = 0xc3b2e187,
            t0_0, t0_1, t1_0, t1_1, t2_0, t2_1, arg, p = 0;
        while (p < padded) {
        	/* Assumes that only 1 byte wide characters are used. */
            x0_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x0_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x1_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x1_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x2_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x2_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x3_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x3_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x4_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x4_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x5_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x5_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x6_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x6_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x7_0 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;
            x7_1 = message.charCodeAt(p++) | message.charCodeAt(p++) << 8 | message.charCodeAt(p++) << 16 | message.charCodeAt(p++) << 24;

            t0_0 = s0_0; t0_1 = s0_1;
            t1_0 = s1_0; t1_1 = s1_1;
            t2_0 = s2_0; t2_1 = s2_1;

            s2_0 ^= x0_0;
            s2_1 ^= x0_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16)
                - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 5 + ((s1_1 >>> 16) * 5 << 16) + (((s1_0 >>> 16) * 5 + ((s1_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s1_0 *= 5;

            s0_0 ^= x1_0;
            s0_1 ^= x1_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 5 + ((s2_1 >>> 16) * 5 << 16) + (((s2_0 >>> 16) * 5 + ((s2_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s2_0 *= 5;

            s1_0 ^= x2_0;
            s1_1 ^= x2_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 5 + ((s0_1 >>> 16) * 5 << 16) + (((s0_0 >>> 16) * 5 + ((s0_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s0_0 *= 5;

            s2_0 ^= x3_0;
            s2_1 ^= x3_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16) - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 5 + ((s1_1 >>> 16) * 5 << 16) + (((s1_0 >>> 16) * 5 + ((s1_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s1_0 *= 5;

            s0_0 ^= x4_0;
            s0_1 ^= x4_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 5 + ((s2_1 >>> 16) * 5 << 16) + (((s2_0 >>> 16) * 5 + ((s2_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s2_0 *= 5;

            s1_0 ^= x5_0;
            s1_1 ^= x5_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 5 + ((s0_1 >>> 16) * 5 << 16) + (((s0_0 >>> 16) * 5 + ((s0_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s0_0 *= 5;

            s2_0 ^= x6_0;
            s2_1 ^= x6_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16) - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 5 + ((s1_1 >>> 16) * 5 << 16) + (((s1_0 >>> 16) * 5 + ((s1_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s1_0 *= 5;

            s0_0 ^= x7_0;
            s0_1 ^= x7_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 5 + ((s2_1 >>> 16) * 5 << 16) + (((s2_0 >>> 16) * 5 + ((s2_0 & 0xffff) * 5 >>> 16)) >>> 16);
            s2_0 *= 5;

            arg = x7_0 ^ 0xa5a5a5a5;
            x0_1 = x0_1 - (x7_1 ^ 0xa5a5a5a5) + (((x0_0 >>> 16) - (arg >>> 16) - ((x0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x0_0 -= arg;

            x1_0 ^= x0_0;
            x1_1 ^= x0_1;

            x2_1 += x1_1 + (((x2_0 >>> 16) + (x1_0 >>> 16) + ((x2_0 & 0xffff) + (x1_0 & 0xffff) >> 16)) >> 16) << 0;
            x2_0 += x1_0;

            arg = x2_0 ^ ((~x1_0) << 19);
            x3_1 = x3_1 - (~x2_1 ^ ((x1_1 << 19) | (x1_0 >>> 13))) + (((x3_0 >>> 16) - (arg >>> 16) - ((x3_0 & 0xffff)
                - (arg & 0xffff) >> 16)) >> 16) << 0;
            x3_0 -= arg;

            x4_0 ^= x3_0;
            x4_1 ^= x3_1;

            x5_1 += x4_1 + (((x5_0 >>> 16) + (x4_0 >>> 16) + ((x5_0 & 0xffff) + (x4_0 & 0xffff) >> 16)) >> 16) << 0;
            x5_0 += x4_0;

            arg = ~x5_0 ^ (((x4_0) >>> 23) | ((x4_1) << 9));
            x6_1 = x6_1 - (x5_1 ^ (~x4_1 >>> 23)) + (((x6_0 >>> 16) - (arg >>> 16) - ((x6_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x6_0 -= arg;

            x7_0 ^= x6_0;
            x7_1 ^= x6_1;

            x0_1 += x7_1 + (((x0_0 >>> 16) + (x7_0 >>> 16) + ((x0_0 & 0xffff) + (x7_0 & 0xffff) >> 16)) >> 16) << 0;
            x0_0 += x7_0;

            arg = x0_0 ^ ((~x7_0) << 19);
            x1_1 = x1_1 - (~x0_1 ^ ((x7_1 << 19) | (x7_0 >>> 13))) + (((x1_0 >>> 16) - (arg >>> 16) - ((x1_0 & 0xffff)
                - (arg & 0xffff) >> 16)) >> 16) << 0;
            x1_0 -= arg;

            x2_0 ^= x1_0;
            x2_1 ^= x1_1;

            x3_1 += x2_1 + (((x3_0 >>> 16) + (x2_0 >>> 16) + ((x3_0 & 0xffff) + (x2_0 & 0xffff) >> 16)) >> 16) << 0;
            x3_0 += x2_0;

            arg = ~x3_0 ^ (((x2_0) >>> 23)|((x2_1) << 9));
            x4_1 = x4_1 - (x3_1 ^ (~x2_1 >>> 23)) + (((x4_0 >>> 16) - (arg >>> 16) - ((x4_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x4_0 -= arg;

            x5_0 ^= x4_0;
            x5_1 ^= x4_1;

            x6_1 += x5_1 + (((x6_0 >>> 16) + (x5_0 >>> 16) + ((x6_0 & 0xffff) + (x5_0 & 0xffff) >> 16)) >> 16) << 0;
            x6_0 += x5_0;

            arg = x6_0 ^ 0x89abcdef;
            x7_1 = x7_1 - (x6_1 ^ 0x01234567) + (((x7_0 >>> 16) - (arg >>> 16) - ((x7_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x7_0 -= arg;

            s1_0 ^= x0_0;
            s1_1 ^= x0_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 7 + ((s0_1 >>> 16) * 7 << 16) + (((s0_0 >>> 16) * 7 + ((s0_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s0_0 *= 7;

            s2_0 ^= x1_0;
            s2_1 ^= x1_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16) - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 7 + ((s1_1 >>> 16) * 7 << 16) + (((s1_0 >>> 16) * 7 + ((s1_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s1_0 *= 7;

            s0_0 ^= x2_0;
            s0_1 ^= x2_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 7 + ((s2_1 >>> 16) * 7 << 16) + (((s2_0 >>> 16) * 7 + ((s2_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s2_0 *= 7;

            s1_0 ^= x3_0;
            s1_1 ^= x3_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 7 + ((s0_1 >>> 16) * 7 << 16) + (((s0_0 >>> 16) * 7 + ((s0_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s0_0 *= 7;

            s2_0 ^= x4_0;
            s2_1 ^= x4_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16) - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 7 + ((s1_1 >>> 16) * 7 << 16) + (((s1_0 >>> 16) * 7 + ((s1_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s1_0 *= 7;

            s0_0 ^= x5_0;
            s0_1 ^= x5_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 7 + ((s2_1 >>> 16) * 7 << 16) + (((s2_0 >>> 16) * 7 + ((s2_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s2_0 *= 7;

            s1_0 ^= x6_0;
            s1_1 ^= x6_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 7 + ((s0_1 >>> 16) * 7 << 16) + (((s0_0 >>> 16) * 7 + ((s0_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s0_0 *= 7;

            s2_0 ^= x7_0;
            s2_1 ^= x7_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16) - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 7 + ((s1_1 >>> 16) * 7 << 16) + (((s1_0 >>> 16) * 7 + ((s1_0 & 0xffff) * 7 >>> 16)) >>> 16);
            s1_0 *= 7;

            arg = x7_0 ^ 0xa5a5a5a5;
            x0_1 = x0_1 - (x7_1 ^ 0xa5a5a5a5) + (((x0_0 >>> 16) - (arg >>> 16) - ((x0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x0_0 -= arg;

            x1_0 ^= x0_0;
            x1_1 ^= x0_1;

            x2_1 += x1_1 + (((x2_0 >>> 16) + (x1_0 >>> 16) + ((x2_0 & 0xffff) + (x1_0 & 0xffff) >> 16)) >> 16) << 0;
            x2_0 += x1_0;

            arg = x2_0 ^ ((~x1_0) << 19);
            x3_1 = x3_1 - (~x2_1 ^ ((x1_1 << 19) | (x1_0 >>> 13))) + (((x3_0 >>> 16) - (arg >>> 16) - ((x3_0 & 0xffff)
                - (arg & 0xffff) >> 16)) >> 16) << 0;
            x3_0 -= arg;

            x4_0 ^= x3_0;
            x4_1 ^= x3_1;

            x5_1 += x4_1 + (((x5_0 >>> 16) + (x4_0 >>> 16) + ((x5_0 & 0xffff) + (x4_0 & 0xffff) >> 16)) >> 16) << 0;
            x5_0 += x4_0;

            arg = ~x5_0 ^ (((x4_0) >>> 23) | ((x4_1) << 9));
            x6_1 = x6_1 - (x5_1 ^ (~x4_1 >>> 23)) + (((x6_0 >>> 16) - (arg >>> 16) - ((x6_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x6_0 -= arg;

            x7_0 ^= x6_0;
            x7_1 ^= x6_1;

            x0_1 += x7_1 + (((x0_0 >>> 16) + (x7_0 >>> 16) + ((x0_0 & 0xffff) + (x7_0 & 0xffff) >> 16)) >> 16) << 0;
            x0_0 += x7_0;

            arg = x0_0 ^ ((~x7_0) << 19);
            x1_1 = x1_1 - (~x0_1 ^ ((x7_1 << 19) | (x7_0 >>> 13))) + (((x1_0 >>> 16) - (arg >>> 16) - ((x1_0 & 0xffff)
                - (arg & 0xffff) >> 16)) >> 16) << 0;
            x1_0 -= arg;

            x2_0 ^= x1_0;
            x2_1 ^= x1_1;

            x3_1 += x2_1 + (((x3_0 >>> 16) + (x2_0 >>> 16) + ((x3_0 & 0xffff) + (x2_0 & 0xffff) >> 16)) >> 16) << 0;
            x3_0 += x2_0;

            arg = ~x3_0 ^ (((x2_0) >>> 23)|((x2_1) << 9));
            x4_1 = x4_1 - (x3_1 ^ (~x2_1 >>> 23)) + (((x4_0 >>> 16) - (arg >>> 16) - ((x4_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x4_0 -= arg;

            x5_0 ^= x4_0;
            x5_1 ^= x4_1;

            x6_1 += x5_1 + (((x6_0 >>> 16) + (x5_0 >>> 16) + ((x6_0 & 0xffff) + (x5_0 & 0xffff) >> 16)) >> 16) << 0;
            x6_0 += x5_0;

            arg = x6_0 ^ 0x89abcdef;
            x7_1 = x7_1 - (x6_1 ^ 0x01234567) + (((x7_0 >>> 16) - (arg >>> 16) - ((x7_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            x7_0 -= arg;

            s0_0 ^= x0_0;
            s0_1 ^= x0_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 9 + ((s2_1 >>> 16) * 9 << 16) + (((s2_0 >>> 16) * 9 + ((s2_0 & 0xffff) * 9 >>> 16)) >>> 16);
            s2_0 *= 9;

            s1_0 ^= x1_0;
            s1_1 ^= x1_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 9 + ((s0_1 >>> 16) * 9 << 16) + (((s0_0 >>> 16) * 9 + ((s0_0 & 0xffff) * 9 >>> 16)) >>> 16);
            s0_0 *= 9;

            s2_0 ^= x2_0;
            s2_1 ^= x2_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16) - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 9 + ((s1_1 >>> 16) * 9 << 16) + (((s1_0 >>> 16) * 9 + ((s1_0 & 0xffff) * 9 >>> 16)) >>> 16);
            s1_0 *= 9;

            s0_0 ^= x3_0;
            s0_1 ^= x3_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 9 + ((s2_1 >>> 16) * 9 << 16) + (((s2_0 >>> 16) * 9 + ((s2_0 & 0xffff) * 9 >>> 16)) >>> 16);
            s2_0 *= 9;

            s1_0 ^= x4_0;
            s1_1 ^= x4_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 9 + ((s0_1 >>> 16) * 9 << 16) + (((s0_0 >>> 16) * 9 + ((s0_0 & 0xffff) * 9 >>> 16)) >>> 16);
            s0_0 *= 9;

            s2_0 ^= x5_0;
            s2_1 ^= x5_1;

            arg = T1_0[s2_0 & 0xff] ^ T2_0[(s2_0 >> 16) & 0xff] ^ T3_0[s2_1 & 0xff] ^ T4_0[(s2_1 >> 16) & 0xff];
            s0_1 = s0_1 - (T1_1[s2_0 & 0xff] ^ T2_1[(s2_0 >> 16) & 0xff] ^ T3_1[s2_1 & 0xff]
                ^ T4_1[(s2_1 >> 16) & 0xff]) + (((s0_0 >>> 16) - (arg >>> 16) - ((s0_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 -= arg;

            arg = T4_0[(s2_0 >> 8) & 0xff] ^ T3_0[(s2_0 >> 24) & 0xff] ^ T2_0[(s2_1 >> 8) & 0xff] ^ T1_0[(s2_1 >> 24) & 0xff];
            s1_1 += (T4_1[(s2_0 >> 8) & 0xff] ^ T3_1[(s2_0 >> 24) & 0xff] ^ T2_1[(s2_1 >> 8) & 0xff] ^ T1_1[(s2_1 >> 24) & 0xff])
                + (((s1_0 >>> 16) + (arg >>> 16) + ((s1_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 += arg;

            s1_1 = (s1_1 & 0xffff) * 9 + ((s1_1 >>> 16) * 9 << 16) + (((s1_0 >>> 16) * 9 + ((s1_0 & 0xffff) * 9 >>> 16)) >>> 16);
            s1_0 *= 9;

            s0_0 ^= x6_0;
            s0_1 ^= x6_1;

            arg = T1_0[s0_0 & 0xff] ^ T2_0[(s0_0 >> 16) & 0xff] ^ T3_0[s0_1 & 0xff] ^ T4_0[(s0_1 >> 16) & 0xff];
            s1_1 = s1_1 - (T1_1[s0_0 & 0xff] ^ T2_1[(s0_0 >> 16) & 0xff] ^ T3_1[s0_1 & 0xff]
                ^ T4_1[(s0_1 >> 16) & 0xff]) + (((s1_0 >>> 16) - (arg >>> 16) - ((s1_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s1_0 -= arg;

            arg = T4_0[(s0_0 >> 8) & 0xff] ^ T3_0[(s0_0 >> 24) & 0xff] ^ T2_0[(s0_1 >> 8) & 0xff] ^ T1_0[(s0_1 >> 24) & 0xff];
            s2_1 += (T4_1[(s0_0 >> 8) & 0xff] ^ T3_1[(s0_0 >> 24) & 0xff] ^ T2_1[(s0_1 >> 8) & 0xff] ^ T1_1[(s0_1 >> 24) & 0xff])
                + (((s2_0 >>> 16) + (arg >>> 16) + ((s2_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += arg;

            s2_1 = (s2_1 & 0xffff) * 9 + ((s2_1 >>> 16) * 9 << 16) + (((s2_0 >>> 16) * 9 + ((s2_0 & 0xffff) * 9 >>> 16)) >>> 16);
            s2_0 *= 9;

            s1_0 ^= x7_0;
            s1_1 ^= x7_1;

            arg = T1_0[s1_0 & 0xff] ^ T2_0[(s1_0 >> 16) & 0xff] ^ T3_0[s1_1 & 0xff] ^ T4_0[(s1_1 >> 16) & 0xff];
            s2_1 = s2_1 - (T1_1[s1_0 & 0xff] ^ T2_1[(s1_0 >> 16) & 0xff] ^ T3_1[s1_1 & 0xff]
                ^ T4_1[(s1_1 >> 16) & 0xff]) + (((s2_0 >>> 16) - (arg >>> 16) - ((s2_0 & 0xffff) - (arg & 0xffff) >> 16)) >> 16) << 0;
            s2_0 -= arg;

            arg = T4_0[(s1_0 >> 8) & 0xff] ^ T3_0[(s1_0 >> 24) & 0xff] ^ T2_0[(s1_1 >> 8) & 0xff] ^ T1_0[(s1_1 >> 24) & 0xff];
            s0_1 += (T4_1[(s1_0 >> 8) & 0xff] ^ T3_1[(s1_0 >> 24) & 0xff] ^ T2_1[(s1_1 >> 8) & 0xff] ^ T1_1[(s1_1 >> 24) & 0xff])
                + (((s0_0 >>> 16) + (arg >>> 16) + ((s0_0 & 0xffff) + (arg & 0xffff) >> 16)) >> 16) << 0;
            s0_0 += arg;

            s0_1 = (s0_1 & 0xffff) * 9 + ((s0_1 >>> 16) * 9 << 16) + (((s0_0 >>> 16) * 9 + ((s0_0 & 0xffff) * 9 >>> 16)) >>> 16) ^ t0_1;
            s0_0 = s0_0 * 9 ^ t0_0;

            s1_1 = s1_1 - t1_1 + (((s1_0 >>> 16) - (t1_0 >>> 16) - ((s1_0 & 0xffff) - (t1_0 & 0xffff) >> 16)) >> 16) << 0;
            s1_0 = s1_0 - t1_0;

            s2_1 += t2_1 + (((s2_0 >>> 16) + (t2_0 >>> 16) + ((s2_0 & 0xffff) + (t2_0 & 0xffff) >> 16)) >> 16) << 0;
            s2_0 += t2_0;
        }

        /* This will be transformed automagically into the desired output format. */
        return (options.order == "little") ? [s0_0, s0_1, s1_0, s1_1, s2_0, s2_1] : [s0_1, s0_0, s1_1, s1_0, s2_1, s2_0];
    },

    _T1_0: "".concat(
        ".iA}5<1U._y'8%lU&,U~gM{L[_UAgTPXyZ{EKz_Qf}r?]S%co_N<@xk4UBl{e=ldG9%f.~!s90(MJ2x@DAQszL%4/{jfT1h5+zmj4$&{*$HdzK+,u=<aib<;&.UX5~",
        "MVDv5X(tj%m:RFN-10.ddPx:^Z7<.CKne7R%N->d*b&17(tt1<hDReSM1rg?W;%mokk+vX=YcXV=%Z&*U9FFGH>uT^qrobgcKE^4ds7T{k~}npASSr]CDNGTbM=BYy",
        ",,,WR<ik<(H?hs^[Xb#h!?RAT5;6|pJD:aYGc59:55L[rcW.tBM1/lpQ#^1uzKhYz^pVSB*En+6X1bZYR~trfI;Adv2i^!+9xDGb/J/+[W%YD^GBRB!ItU*r['CFJ,",
        ",R^$NzlQyZ[i:~(BrdS6hfLAC%z1}YZ/vMvIq8[1Q,APi^GFH@/1{BI:M(Xm!mOBvagom>AoH#.+fln&wBY6j[?iW8;'A@:lP~>8gpSPjQp7#F{f3j*Sjl[M|qhl/<",
        "[dD&P#lklD^KXd/oE!SE2EwTZTu*g=G@-H6]I~F/gkn{sbKUD)Nm6q@cp7RwqL{!lR%e!;u39kP>Aw6~m@WHHPkfhhW<=O)qvfi&GCdZblC@t^ak0lqK/>N<5^E#ty",
        "&S2/px7MZYbHnL+%fbRiU9i3r+2VkIpViD#>T{7>~sagbrWs%F1tga)K3~U&1a5shQx@/3V$]lnC*eaW+#%}:#b,rUZ7tmiZSUrNkH%?~8D~))i(i6xbXWZYhm<i;;",
        "RW%UN>zw=TlQIjYmJ[HkOwNrDd;gZQbwI6MQvRTX|<5rl67qA7~}@~9T^Hu8W?OTK^yrm.Y[yoHu]OD5b<:<#W:DC1;D~$k9l'#sm.,/r,/p+hfm:e4edJspm+#oU]",
        "5k|F-'ms.QT{ay*1NEti5pH_-j@@^|nw$^gRE#}8m[>H+UflV!5c>?zBzSlQLrlbJme/2zlQ^C4Q*4^?E<J,_X{{,_s[sJfaMQe6P&>Gb9w7@{R?u,.h+Jq)EzM(&f",
        "C(7r'^rqSjm-lCv^g}AsB5N(7WsZ?_#h/Tjo%;<F3J%V:eAJ|zuU>s#JK6Q)Xk[BBV+3|^A.Vrx%?.rxo4SSHzhCL*2g<14Xn?:}jet/?Gsi-#nHLcszyXEs;5.qaM",
        "zYO]>d6H|LNP:XG1wTG+AO1ub}4k?;;WTw@oaD!n-fq=,BoVVoM+tsV'<|tKm/6'c}XpJ({Er.5/x)t*9y[U,#tC*J*M30v_;R5azl[)nNs-K@>X&RLtQwPEDVKh7A"    
        )

  , _T1_1: "".concat(
        "RxB8KC]Mb;Unwf=zvEJ=I'u<s@4.^m&R_w-%.F!d^nC8iTAX-x{:H2lb7c:h7^?FZ!A#)XjNnwsR#Z<'Fc9zl.Onx^PXM!Dvqq9vPKX.#L-T(B'.(]S'-li[?(LJ]z",
        "ajdBt.%qD#,9gPFf(h*pAgYY1HxSV4KBD0s]sp('7P*MpIik9|zjG?rLo|c$,]:=#I_&p=QQKR*SL&X3.C(.rKAlhyUL-fdIq^:Q4e[-S!JU#H5w?{g7)=NVst^X|i",
        "C_wDQ@rx=Wy8#TfF&ub,gS&!(xP8TSTE9M3&2GKL_!h;ZNkc(^K_l7Rhui'g~dkJL}?d~2fl2mDPAY&=M/;GM_*qd0/;2VfOq~pDJdoSB7[v>sr>2Sv0_.vru^,l(g",
        "%nFXL9q2Uu|I@)gEOZN[:~,n5lTbh]U!%wWaY[Ja|p+H/t!ZC+RhZjNe5Bwv9fST<th:~e'E4La+Vxc,un4|]hh50,^,L7OU*sD8oYMC0buS~uZ67q)*lr]$:OwEn&",
        "@6B{*y3zP6JB_wJahs>@ozB(BbDZlJh*%}uw%:E;ZqH^p&35*l:bExzys%Zzmi3&Sf(wr%7p=+f%yE'37&;&>R=H)kq'uudqFzT^LJAxn5XZ>;S7b'V,<9t&lLU<#c",
        ">880u?8:LE@rs;'4l'>)-M^A2].No2t|.SmOQxj%0Sqa2?+kTaU#TkZvKu&rOxYioCAA[=B>m+BK{wW.r_/7I0j#b^%}V_HRw[Y)FRqXjHF1>(z6]<c;zld1PY9nF&",
        "'1:GJ4!h@}bjnp.:tdA?gY+jwfs0H+sM,Mf?a7j=ElUPf_S1M_sNfTkb7F1'w'LC{cOfs0E)TH|07$]Z8O>Q,z!8:>DhO3A7y-z-B#8iM'u5!4-LTJ*F#OT7QDI&xk",
        "J]f6l}Up^JeK7N$_wj_(ELZSR+d+88:J>x:Q$J@AS_hS:I|wM!l!e#r$~(19]4K/$LB4dnNe<y5e6=D(Pun^?v9Taz=bGaLw8M_jfhd~iK8Cf^2<XPSU(y*Me:st!H",
        "Ao8%8.dESMH>%^$f#y<h3$-'Y##r0aHMGG,X$dj'!8rJpdC[qI;K;8uKs4r|>e#]a]i#kZFPV0+mo?VYgJL3LAct5dcEA?U.isM!oyjT@N+#Am&C#a]R9^RKd=?U->",
        "VG77Tp0nk)}?@[.>havg_e)jKc0}XS3#s[FF'.?]F5R;8v~wdv5,Z#@?,m)Uz$&1X68U(Q3jb%/[95}/QMF;:Y5B_?VKPI]#K<0WVm7<EG#0:~l{keqs7C%1B^E)1C"
        )

  , _T2_0: "".concat(
        "nD9k[Q)v:fq6ut_:V}BFTO92U}te8MzxQ'}j:bBPOB]#&i(skLHrAbf}wnVZS1$VD%o7?c,TbQ5o#X;EA4F?~Edbeto..dh,-XbbEw12E[XXP5efVn[n_Dk5^t.<R_",
        "C=w1Bj~'#][Dzk@tn]]Un@%Ghm[xzFqM7$%L%]c6!hS>oP>yfm;d*g?dlDl*xW}=y]5'TrB%lND7kX0iMPB{SfafeJal.]FyyLh06*z.C.3RKYr@4<DixdT1UWm6hw",
        "B=+]Ye!Nx!yWs_.!PU=#~8@/^s&$LuY:;{NYE~Fx#)f9sn~%~,+INM)*rkxpuxH3]@r{}S^WB<8ubW5{+=+ou,LEy[qv*r2y9n*Fwkq$T6iW,S/z9E1K8pu14ngK:^",
        "g%?eApZ2BO$cSfe*>8@Cw&Kd*/vv{'do_<E}|_/P%+tfCq2ihL{bMG8mYm.ADUVP7zy6KRTeOIGe@pJ0B8R:/]8RAgPI[7;.rMA=|h(fxG&kaMLO$m{e7[(}^&E%WX",
        "yd?M/'d+_rog<wR%$7M3*]}Fb.HqIb]fF1n.U'x+n__!x8/$npDq&KU+]lx1x21&IN,CX#Ya7nzdk#sZAA.wL%l#ssrQ.d$@5kWXX@.ET|dXh2?iINE_k{w&W_oN;a",
        "#H69*STJ[Gfzk'EFX0pBEyf2RR+9%<|^k!ZxNg;.b,lB&GMo%Xb,E>NZcqz>):l1}$+H'C?8$*V6Q,Z@Z8omU}d0;|gL!$P9{FcHeU)?WL2{oTN@X;!pc0Y|j^s.[z",
        "5rb~UF%^%]sf1J*^f=Tr]b:eN=e|IRu;R:{!(hkZ?&by_u/'tr9UG9EnNwH+hMV.|@^DH*$0RYZRFP6ecIsIrng7^Jri$nHA|o7cDLgAL&6B,YQ18'w!LAMdcBk^Dj",
        "]9L,lFf^%vnhW{Mw0}uI2R|C}Au7Wqx@Yd3W<m2#$z<)+59w7vyb5k@eF#4VE~bY;bif<47UAm0vaywY4kB9d4IBAV8n6GhR5h67a8*XMzuiE}06]5#?,msk9Vtclw",
        "-]YJ]%z}-(f=A5PEbd!o4]qx#j98NS2=h<]<&/yk.,V+@z=nEPZqRSXJ$rVNdwXWTfh;]0V?,Y&7=4|!P4AD44Z6cxo]tTRUgUha$h6[j',H:vN$W,IN#0vdfYk,{2",
        "vr&De$@],hneYO76XnaL53aXt'U~nr/Yd</Hv7!h*#W~SS%5>?dk)p%M0|{n$)*NQS_gu.fy#zhbNxU(S(L4i<B5P%EHO>$1cwAVYv(FCe_S-Y}$iNET]n8BbBkJ)D"
        )

  , _T2_1: "".concat(
        "j'877ajG{<*tP+aQKTU:Wg)zVo#7O?u6:%7h;{Hm^?#r63:]!N6&R>&_}YQ?*&f62c{G;cm?;os?ezgh{OESaS4x#{NuzNmssh_E5kPX&,st$'_/nI!pW7RLxF}B6=",
        "xvK%wZaxR|.nn+lHRI#?}]QN7V|r>*#*^N%xt{GZz:lD~W}Usw<).Zv6g//_7.(Ny&b~{t!]%g3/:x&D'~z]SsqlfdwZNG]IXP~N;Tgx:;3/vP'PR)W>hJ5#GSi-H0",
        "p#C?:lzbErASp4/8EsX9WcbBQ~0kS(ncPpRJ{q8H#PanKU,rB&z,*9=+VoHA2C[HSy9c+l<vm?OhP^t^d<gx6*5vMYO%n~b=3Un$CQ.2RQ.o:/)kcw<60u'@0JN4$l",
        ")o<h)d%,?S|@$~}k~(EvlQ;R-!|;ZH9jqLQ^~G5=V9Q.}<M6G.X.B,5ImcXW#EO9hX]mJs'()[Y_~VjYoNR*=z~[y=z@'VgpMZ!$w=@<l)6x,O2qz*4t&>kN)20xX&",
        "0Tz5R!tCbi3/qSgFaRpbeO=>eI]j>=C{-N[%nu%NAFy$0>6;q!@)L*6(eU_~nlB{ZQQ5IBm7OI,:z]H8,Cd'@@ua.=hu~5:,2W)!QCqk0HL*<6AV2B^'kT}!A+w]nI",
        "0[W_gjV+0e'@'N'd1XFuqZ',%$o1}D8]D'+%m)>3:<A)Jv9Lc[troC|yt7L.yF*yJYUu*$#I#PPVowlP48.Lv]^!Od0e^~#I@Gq6;uTot2X8QPqa!uQi%%!,URohI0",
        "<a^fcw[JP}>V!.!_Q^E<>II;5&94&L'@v6gd}q7w?C02!*9Nm=-E5FM?7Kqt)Zk)b5$E.]!EJ'x~OssIvK6{4JnOudxchWVoX}+mZ[HkdFmh@'m)Z!FXBDpMcxU[_i",
        "HWI>3rla,kzvJO*F$~$<Ie_tIS2n,oBK,Zmt}jHOc'>|wjGdU^!9(3quoOE%L&14A4jAppE!A%ZL#$-C+zU{^?z7S]we8f$U^i]P]$o!o%.C<>PNWWS>#O~FRH]He?",
        "Rphar=F7-&qd1K[SkYhZ~1wqq*DP+,-T1{Da2ruX[,2!Uclv|zqodtt3W(]}&<fuUuZN5(x#tLJJZ2Rupxs&dF+Z)kj1[=#P}aFSrv1v#N!6jUtfVm<~Q9UPZgL1/0",
        "{<p*v%1TmrGB.$hCPZ5mS|u[9JSPoX5Z)<9<n[F(jwcAK*33^,LcVsBJIC2a,Udm0%*|w&dp1/uf)G>/tU]1Es*w:+Ur+y?4pR(Yp/k0GQ7ZqBHn9s%66%h*j1X;GD"
        )

  , _T3_0: "".concat(
        "O3)phBrO#$34$2OjD[y#CqlWDSx)R4~z>$-21+YrS']@BB}{DBXQzn.eR*dHFe%?Hxr;7{tG3@}}ybL6MuUX|SZo9QdM|@.gi#qT4)(F5wG^oGI;9Wh:j!7*47t%Wf",
        "7tWmmr)B@mt)5,t@2EIhw5Uv}Qs>Kp)l8Y7zGJ}U8XTdd2B,fQ&MhGnDx,&XtR{rwwVy&,m<G|NqUiQwE9Q7frJRO^4}1]GuA_c1p(T3aQJTL[i8jkEdnGRWh(i)F:",
        "PGX5N?WX*J<Dri<TP~D8%<xoQ&:(jB#I6F?I+g5FNL7w^6c'?X>2J$l%zNi87!1<'&Ee/gM416,xCU|T$b1VSqhe-8gxrN?XnJ&9+|PA&t+7|&gSA1xmzZIT{!/Dv0",
        "3G=R;+?/jOu%QKyxf7]]Bf{,O4.;tW}_#[v<i$w8^eG<1f;P1$JeK{:InN*C}%W7HVs4,w(l_)rp7vXSXF^tgy}w:q*+wp8,jst[Hr)D?|HE{!QyZzCW(#No<lu$dc",
        "W0mz]0;jxbJSqEDNO[ZwH#RnR&W3wy7alOyI{{S8Wvn:lhBv+2^_&4bBQX3op4Qa(^L]Jc(g3FmCj+&qLur/w-:fzuK2,W3$:eGLnCws.GkK_&1>{1}vEU]YZ(rK_r",
        "r^W[OB'w@rD[isg6q;G,>1z#byz!c8cTfnq9{#kf*E#^D%oF{3%d4*zwnE,EVd2IFy|BF'?l{tPaDIG]I4rMd==A2+zr6k,0Rq8s90N5G)bNA((gO2@8Q_sr|(j8pI",
        "Ph$ttn|hGR{'-ij6r)mSbg5!*7Vva99y|T~feF9fD2NOc]jf~GwCV]D5~SN7DyR)UU$(@_|K1Q.t+(|yKp)9^.SFB{{u3%](>Fayuwvcst*jpkL]D_m,_W5.7KPoB<",
        "]31~Pdsbxw%qeP98%91(g&tR7<vd[W.OIdQU!v3D}iAWH^.jx@q+6XZVW$WT(bS_#}jZ=E65&tekc<j(:iT!bWPqY<=cx^q013%lEe^vTc%NWX|?IyEy>'M=%[5g2F",
        "w[umJ5@dYJa51Iqeqnhjg/9a3l*ANY+qs?Su^6Y9E$FNL+R.KF;duRdlltescqRc>xXx22gdj@?l>04sfa~BS[-PCw.nuLn7{)(oaZ9cGPMHa*b:wxA#'6O,tD@Fk*",
        "h{IOb[d&1uUn=~;,8xyWq^JQ!Szd5z-ZRnrScep)Ab-[C[Tt9GySrQsE.!aNTG1#B{,Q/*xn-'6!ambmWfv>!'-Q6jgP$o.rxHLiM6dK(WGF|9gUzN2R%Vv,33U&PR"
        )

  , _T3_1: "".concat(
        "ZiEO]xI~)5AJPHN@,<n,[^85H]}ufN6?=CvK/2oPgFIW5W)DCvj)P7=8dsXQ'/B1]Dm8~$Za@F3UnkQS'c5r2Hq<rnUg:cz(W4A*P||^G<t;@FrcNK@c8z/~i2wz*e",
        "qCcL1s(N0CZeX;W6X)C3T}p>?u=I<n&'qd@u9d@5C^z[ptT?}Lr4zbB3M,t?my(f#kTN=1,>R;+~j[4iYpfv'uP2G(u+oRjJ%rIwljp%',gc)Jd;CvI)IZr%>lrBf_",
        "P^9cYaaHvJsxnd0=T-!f9=d0|k:ksjT7u=:)'H]Xk%{$08XR(|h^m9^9/VHQ$.>rSJuGN/<jIB9%DZb!;{^sijF$tOd}:Gv3;{^GzKLiJHuC>s{|DS5zRwd_<wN{d=",
        "QgKeo)LrafS)Qs+I0t)UXj2cM+sl1$PB;u6zU_KjfB!6Ufak@u>wB.P5IdLT:(=/T*o*3FTGF.L,89(|BWgy)lY*Z@I)}tOR$x3=Ba-mcNSLiD_V(Z!NCmG:ITp4%2",
        "S~k,StIw&zyLvs}lr8O;fcQ]vrumEsx.Q?*@|qma%^@rcg^l:,h'V>ooiPVsUPzR50@!9LhAYS&,i24A]zy&mX4VJ)OZ[g+ICrIx]_$k[b9iV5@qs3UL2Y<CrXCtzh",
        "a|KZ(?D@1uEM]IlpiFxYu6sLMsOzU[XQrjhP9e,Tgf(eD1j#^JQ&s#dxh@ZyUG<a~J>Gpa.S0G?'?*Lc[~Pm8eT;;>Nu5k}P6p'a)9HHve;MyTdT!7U?E662X$K|5'",
        "(wCgM_]h5KyWvcuQb07pPqP&'=(i3bC-TXp[;TZccRiCS0^RgeYm)%kD?8;5%>mQY}tm(nBFf!&mIE7+$DY,#YoE!|pNpZazA8kI-U&Q&&mwzNf9]ytB}@?8MTUMDP",
        "c*U]l%5{ckcv*Hbs7bv2a]PY]hB*cST>%J]MFH>Qycn,pVdC!SW028n'X![HO1(VOb-<bBiJ7s%*eVROPaaKSh1.8M<hT.B{'rd6r9Z7w1(YJ<J>6p|5<O.]3)e*(3",
        ">FCVHNFAxdlg$(rg-*{uA1_j.mg9yD(CFQ_XA=S|fKz|hHXQ,N5PPxi#D*hep&dn>r1<8CP0c8d#)Zki'<@l}/ReNj)LznR][X[l2=r7+H~zot)aO/b$Ca+DvWXT<q",
        "'sowZni63aAr2R6m?*@#k4^r4Jn]5@FtJm3}~[g=;2smfo%4V4^5q0q!6#BRzblwbFiuO.f;_~<3bP*l0.j+7.(T71w*Az|f[}I<D)08Z{j(47*Zr[Z/Nq%VUrUU.E"
        )

   , _T4_0: "".concat(
        "$?mxj]>#}rrWiw+;XaZ$1h{?Z5WY##wD,#-~L|%jJka!^x8gH|d#L|mh{,mJ7)N3OB4TetTFl)~Oib)ZEEfvG+M&^I)GYn>F:e8zPDSaFcG$~Jj>D2DTT,R~|c5_qN",
        "iIfSevF}(FSwpW2v1tiA/qrwZ}Z&C.{5m./p!-$LAt17_nL^27yi8a&0O?fj(CDT*H)H.]g(I.y~h|UEw(l?=b)]Mg[>@s~R*JX^4_&X%wxI%+M}Cw)}u,mS*[!@c6",
        "cl*M|Z/_f_Y&ksdDLed/:~J2LI9IzzvjN)W9:7FI!Ga+%.r0c8/xiFFKO,4o<H${n%BB(Ii,@N]4Yrro?YL<{vip+wW)7Ujucmff&$H/!2np]5L&m>9BSh9$)<+8S0",
        "V/j&dZAw%rcd97k('*=horhP;<Fa(&>WUqJw91S;IRrQb.0p:g6|&F+!B/U_~q4;tIW[+lGj9[F48*8[$_cCI,-lN+U:T(S<BN/z4od%K#PSgfA}4t|2_Bazd!u*h|",
        "&uKIF.YApiOWD8'^&yb8+I_,K5X)6!gF@rYthLv6G,V-9^q;LW:/$jN)W]x'Q*|'ynua6C35C*G%)[h}Onz.?q)A&#C2D|1k':6D+T#VT5lXnqL[w].x53GX,^!!H'",
        "(GuVWu!2wmjm{KQV}?$+v0z{$o@=MdMzCy1cT4F[Bt-Bet.t-92//$Wz0+j2Zg#sN)9#w?PbXwN,n4W$>}+%YeIjQ<&k'$jbh$5lK,l<Kf_i9',OzW5K^J=n4.})X3",
        "D?cS|z4'ghd/7Y{Yd%#oZy/[TSqVuALo)o4H[]+IIZi6z0doLA%!&ZD=/zU'E7zh+U@/+<%5Cy0UctT0o+leWby46d]9N(EJ!f=(@&~MOJ'aE|c2F_t~7lrhth=SXq",
        "(p5'gFZAb$#!Gwc;=a[V-i2G?r}qIVh_(%0<)^yBMLlqf2H;=@03=6<&<iIjci]>>m#5w/_Z0ae.i&UIpH%}9Q-6Dww,ltEFh'}*GzoMXLNmPw[{VVXMmYs]=47~Z9",
        "E[LL?SLxjtwUO=AR]eW9dXZ3tf6D)g=-zh~0?y3EBd5C{z>|H6_kqx8i*09jGvs(m%(FC!<:I]Ad@pBmi*&+0d!&vfMKx&lX7ZnFe'x_l.STSc'7yci,1s,/EX]s0D",
        "xWZF95ovCab2Q{jFd&)93Qn&sQ@$U9-ChrH|=jjjGh|#)PTSl'*XrRqZRe#v(k(&M*9dC|O,i59N45;|U=]WfS5,A&n}[7MW3JB)AD11XovDcKUC+9kfDhJolOZ<cA"
        )

  , _T4_1: "".concat(
        "qB,)HdBm5x^HSVwfCd|1gH{gP(P8Tck|S0e0xVlUf_aE[.P#9*Z#m3)_NrOD'f^D-Q,~]JuxP$!zc<Vf_Ly1of0ZKi-xdr.~6~pe><S}ldevI5D|<Y&>K}JA^K5wd]",
        "7Bo2[8>)k^~+ZRSbDy2)oxi&N]6*GEG>FkL~j0:$GegJI|tx*v!e<yU:)%x~6V}m*56mEJw?Mt4noL/+]~#9iF63Yo1(a;0~RB^p4c6<I_XxM!L<C9ef&{_P%.$32J",
        "LX!Or7dnEZy_z3GJ%~^[=ZSjLP8#u+O)d?DES0?j,(*P@Z%<[I8lVE13ac?,iQBB(4e&d1Q8-l'U+,Hi>F4^ovnmNWf27ziOjy9_A5tqw!C2zq=$ruBe7X?u:C?N=j",
        "*z}6}(XEM+='<rbKgQ*N@7GPM6}{~Ln:2is)@*CW2*))6%mu^q0,&s$ZoCqW3A_}u[=_(O4=6d^x^>HG[aZQ1w<tMS#Q5ud?i)N982apT3?Ol:i]NsCOc=X)0}z%:D",
        "$2A?JC}{[MvstS>Zuh1{Ahl*?A=~LLYcArjNB#;j1J,}zvKX:h{QD9{YioB39NmCV*t^$,#h&.un6ZL1jGaC}54(Lh3:tAxCg/e|7DzvXnR,{cV+XY6X@2=|Z0j(M>",
        "ft|n(wqsXy}2|v$~(>]flJFh[3~q9cX8SGU0!wP|[J+L2<Mji5s$N:=[?+73t'm)!L}X7rvQXfg%-/=P^HM<$jBK,#h~d;=VE|nYsF!U*uq@gt_/!Y&)f1dSA+f</L",
        "&]7}7$sqkJ,K4~>*P&Y%6c|Q>XRp-/}8d>[T?q*13J:zA/i]z}T~.7nJ)&u=N;I~=*Tll267:YUA1d9^T2_n_YL#qRoH/.3SZpYMolLM=2zO%{Qdj)9F_vpQ)XS#d'",
        "3=Kn4%[-v59ky(npTn{c.q_)x'JS2__Xg:[#2z92@+8,N#)+JZ-2!=jTR??H6*m$Xpc^}]AN#%i^N*5UV5b2dRT5X9|EuL2LKJ9kjs0!?M%{{VPckd')V~+C^d4'xe",
        "Z=?;UF4epwdX5Ms9VR&gAhfX(OZhZ+ccS_7(F+IW7.Z3bnS$pd4K_@YNY[U/h>TPCfj#Ah{|fo,YII6N8lwu~X&wPgIQca>Y'BG2pYMwcGe+Wj8)juO9=5pDleuW)c",
        "P}cb+A[{x@auo~Xh?+vu]<U/<m]mq:lpgp;qO>U8P:2?cfv]vL9Zvf[ho{fjdyls0h=EX5-1PLQv?DR1bE^X$6+)w^g']y%F{EO!$UkS_rk<vlrpma?JdGwLPQf4NC"
        )

};
