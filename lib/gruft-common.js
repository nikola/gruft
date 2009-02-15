/*!
 *  gruft-common module Version 0.0.8-2008xxyy Copyright (c) 2008 Nikola Klaric.
 *
 *  Licensed under the Open Software License 3.0 (OSL 3.0).
 *
 *  For the full license text see the enclosed LICENSE.TXT, or go to:
 *  http://opensource.org/licenses/osl-3.0.php
 *
 *  This software is part of the gruft cryptography library project:
 *  http://www.getgruft.org/
 *
 *  If you are using this library for commercial purposes, we encourage you
 *  to purchase a commercial license. Please visit the gruft project homepage
 *  for more details.
 *  
 *  TODO: replace Math.floor with n >> 0.5
 *  
 *  http://wiki.mozilla.org/Dromaeo
 *  
 *  TODO: use this for exception class creation:
 *  
 *  http://webreflection.blogspot.com/2008/05/habemus-array-unlocked-length-in-ie8.html
 *  http://www.devpro.it/code/183.html
 *  
 *  TODO: use if (! ("console" in window) throughout for object detection !!!!!!
 *  
 *  TODO: -~x and ~-x are equivalent to x+1 and x-1, but without (possible) parentheses
 *  http://codegolf.com/boards/conversation/view/160
 *  
 *  TODO: use if(~myWord.indexOf(myChar)) ...
 *  
 *  TODO: in Opera and MSIE use string[index] instead of string.charAt(index) for more speed
 *  canvas tag in browsers where supported
 *  
 *  TODO: http://www.ilinsky.com/articles/XMLHttpRequest/ for getting JSON from server
 *  
 *  TODO: in MSIE use node.text = value instead of node.appendchild(doc.createtextnode(value))
 *  
 *  TODO: in MSIE use [].join(""), in other browsers use " " + " " + " " ...
 *  
 *  GET PIXEL VALUES IN MSIE:
 *  This works on IE6 and IE7:

var PIXEL = /^\d+(px)?$/i;
function getPixelValue(element, value) {
if (PIXEL.test(value)) return parseInt(value);
var style = element.style.left;
var runtimeStyle = element.runtimeStyle.left;
element.runtimeStyle.left = element.currentStyle.left;
element.style.left = value || 0;
value = element.style.pixelLeft;
element.style.left = style;
element.runtimeStyle.left = runtimeStyle;
return value;
};

DETECT Opera:

You can use the method toString to verify whether window.opera is an object indicating that the browser is Opera:
if(window.opera.toString() == "[object Opera]") {}

 *  
 *  GC in MSIE:
 *  
 *  The heuristics are we do a GC on the next statement after any one of the following limits are passed since the previous GC:

0x100 variables/temps/etc allocated
0x1000 array slots allocated
0x10000 bytes of strings allocated

The array slot heuristic was not present in all versions of JScript -- we discovered that some ASP pages were producing ENORMOUS integer arrays over and over again and never triggering a collection because they were always assigned to the same variables and never allocating strings. But aside from that, the heuristic has been pretty much the same in all versions. As you can see it's a pretty naive heuristic.
August 31, 2005 5:58 PM 


For Vista/IE 7 (jscript 5.7) we did improve the heuristics for the JScript garbage collector. For some applications, the performance improvement is dramatic.

Here's how it works:

The initial threshholds and items counted are the same, but for vars and slots, they double (up to a large maximum) each time a collection recovers less than 15% of the outstanding items. The collector thereby roughly sizes itself to an app's working set as it it grows.

When a collection recovers more than 85% of the items, the counts are reset to the starting default.

The threshhold on total bytes in the SysAllocString string space does not adapt - just the vars and slots.

To trim memeory usage once the app has reached steady-state, a collection is also triggered every 10 seconds. For the timer-triggered collections, the threshholds are not changed.


 *  
 */

/**
 * @namespace gruft.*
 */
var gruft; if (typeof(gruft) !== typeof(Object.prototype)) { gruft = {}; }

/**
 * ...
 * 
 * @author Nikola Klaric
 * @version 0.0.8
 * 
 * @namespace gruft.*
 */
gruft.__common__ = function () {
// new function () {

    var __name__    = "gruft.common",
        __author__  = "Nikola Klaric",
        __version__ = "0.0.8";


    /******************************************************************************************************************
     *  PRIVATE PROPERTIES
     */

    /**
     * ...
     * 
     * @type {Array}
     * @private
     */
    var _exceptions = [
        "TypeError",            /* Raised when a supplied parameter is of wrong type. */ 
        "RangeError",           /* Raised when a supplied parameter value is out of range. */
        "SyntaxError",          /* Raised when an interface in the gruft.* namespace is used incorrectly. */
        "AssertionError",       /* Raised when an assertion fails. */
        "NotImplementedError"   /* Raised when an interface in the gruft.* namespace is used which is not implemented. */
        ];

    /**
     * Execution scope of this module.
     * 
     * @type {Object}
     * @private
     */
    var _scope = null;

    /**
     * Collection of registered addins (e.g. profiling, XPCOM-support).
     * 
     * @type {Object}
     * @private
     */
    var _addins = {};

    /**
     * List of interfaces in gruft.common.* with defered import.
     * 
     * @type {Array}
     * @private
     */
    var _defered = [
        "profile"    /* ... */
        ];

    /**
     * Collection of instantiated singletons.
     * 
     * @type {Object}
     * @private
     */
    var _singletons = {};
    
    /**
     * Collection of test vectors for digest implementations.
     * 
     * @type {Object}
     * @private
     */
    var _testvectors = {};

    /**
     * ...
     * 
     * @private
     */    
    var _random = null;

    /**
     * Symbol table for base64/91-related conversions.
     * 
     * @type {String}
     * @private
     */
    var _ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * Conversion table for base256 -> base16.
     *  
     * @type {Array}
     * @private
     */
    var _BASE16_MAP = "0123456789abcdef".split("");

    /**
     * Symbol table for base256 -> base64 conversion.
     *
     * @type {String}
     * @private
     */
    var _BASE64_CHARSET = _ALPHANUM + "+/=";

    /**
     * Symbol table for base256 -> base64 (URL-safe) conversion.
     * 
     * @type {String}
     * @private
     * 
     * TODO: urlsafe_b64 encode in Python: -_
     */
    var _BASE64_CHARSET_SAFE = _ALPHANUM + "*-";

    /**
     * Conversion table for base256 -> base64.
     * 
     * @type {Array}
     * @private
     */
    var _BASE64_MAP = _BASE64_CHARSET.split("");

    /**
     * Conversion table for base256 -> base64 (URL-safe).
     * 
     * @type {Array}
     * @private
     */
    var _BASE64_MAP_SAFE = _BASE64_CHARSET_SAFE.split("");
    
    /**
     * Conversion table for base256 -> base91.
     * 
     * @type {String}
     * @private
     */
    var _BASE91_MAP = _ALPHANUM + "!#$%&()*+,./:;<=>?@[]^_'{|}~-";
    
    /**
     * Lookup table for base91 -> base256 conversion.
     * 
     * @type {Object}
     * @private
     */
    var _BASE91_DICT = {};


    /******************************************************************************************************************
     *  PRIVATE METHODS
     */

    /**
     * Test if a given object is defined.
     * 
     * @param {Object} object The object to test.
     * @return {Boolean} {true} if object is defined, otherwise {false}.
     * 
     * @private
     */
    var _isDefined = function (object) {
        return typeof(object) !== typeof(gruft.deadbeef);
    };
    
    /**
     * Test if a given object is an instance of any element in a list of supplied prototypes
     * within the namespace gruft.*
     * 
     * @param {Object} context The object to test.
     * @return {Boolean} {true} if context is an instance, otherwise {false}.
     * 
     * @private
     */
    var _isInstance = function (context) {
        var a = 0;
        while (++a < arguments.length) {
            if (_isDefined(gruft[arguments[a]]) && context instanceof gruft[arguments[a]]) {
                return true;
	        }
        }
        return false;
    };

    /**
     * Return an iterable object with keys constructed from a supplied argument list, and true-ish values.
     *
     * @return {Object} An iterable object.
     * 
     * @private
     */
    var _dict = function () {
        var items = {}, token = "gruft.f00e6a6f9b7b4886b9872039040a0e87", head = arguments[0],
            keys = (!!head && _isDefined(head.constructor) && head.constructor === Array) ? head : arguments, k = -1;
        while (++k < keys.length) {
            if (keys[k] !== null) {
                items[keys[k]] = token;   
            }
        }
        /* Make sure that iteration actually yields only keys from the argument list. */
        for (var key in items) {
            if (items[key] !== token) {
                delete items[key];
            }
        }
        return items;
    };

    /**
     * ...
     * 
     * @private
     */
    var _setup = function () {
        _import.apply(this, arguments);
        for (var d = 0, iface; iface = _defered[d]; i++) {
            if (!_isDefined(gruft.common[iface])) {
                gruft.common[iface] = function () {
                    _import();
                    if (!_isDefined(gruft.common[iface].__shadow__)) {
                        return gruft.common[iface].apply(gruft.common, arguments);
                    }
                };
                gruft.common[iface].__shadow__ = 1;
            }
        } 
    };
    
    /**
     * Search the gruft.* namespace for modules which provide addin facilities, and import them.
     * Only modules declared in the same scope as this module will be imported. 
     * 
     * @private
     */
    var _import = function () {
        _scope = _scope || arguments.length && arguments[0];
        for (var symbol in gruft) {
            var object = gruft[symbol];
            if (/^__\w+__$/.test(symbol) && typeof(object) === typeof(Object.prototype) && _isDefined(object.namespace)) {
                if (object.scope === _scope && object.scope.gruft === gruft) {
                    var ns = object.namespace;
                    _addins[ns] = object;
                    if (typeof(_addins[ns].extend) === typeof(_import)) {
                        _addins[ns].extend(gruft.common);
                    }
                    delete gruft[symbol];
                }
            }
        }
    };

    /**
     * @see gruft.common.reflect
     * 
     * @private
     */
    var _reflect = function (context, implementation) {
        var blueprint = implementation.prototype, name = blueprint.__name__, id = /\w+$/.exec(name);
        if (!(id in _dict("MD5", "SHA1", "SHA256", "TIGER192", "AES256"))) {
            throw gruft.RangeError("class <%s> is not supported", name);
        } else if (!(context instanceof gruft[id])) {
            // TODO: http://ejohn.org/blog/simple-class-instantiation/
            throw gruft.SyntaxError("class <%s> must be instantiated with the 'new' operator", name);
        } else {
            _import();
            var codepath = "default";
            var signature = id + "." + codepath;

            /* Create singleton and reflect fields. */
            if (!_singletons[id]) {
                var Singleton = implementation;
                _singletons[id] = new Singleton();
                
                /* Add profiling methods (optional). */
                var profiler = _addins["gruft.profile"];
                if (!!profiler) {
                    profiler.decorate(_singletons[id], this, signature);
                }                        
            }
            for (var field in _singletons[id]) {
                if (!!profiler && field in profiler.enumerate() || _isDefined(blueprint[field]) && !(/^__\w+__$/.test(field))) {
                    context[field] = _singletons[id][field];
                }
            }
            context.__name__ = name;
            context.__class__ = id;
            context.__repr__ = blueprint.__repr__;
            context.__signature__ = signature;                
            context.getCodepath = function () { return codepath; };

            /* Setup automagical output formatting. */
            if (_isInstance(context, "MD5", "SHA1", "SHA256", "TIGER192")) {
                context.digest = _digest;
                context.__digest__ = function () { return context.digest.apply(context, arguments); };
            } else if (_isInstance(context, "AES256")) {

            }
        }
    };

    /**
     * Return an option from a given arguments list if defined, otherwise null.
     *
     * @param {Object} args The arguments list.
     * @param {String} field The option name.
     * @return {Object} The option value or {null}.
     * 
     * @private
     */
    var _getOption = function (args, field) {
        return (!!args && _isDefined(args[field])) ? args[field] : null;
    };

    /**
     * Set default options for digest and encryption implementations.
     *
     * @param {Object} context The class instance context.
     * @param {Object} options
     * @return {Object}
     * 
     * @private
     */
    var _setDefaultOptions = function (context, options) {
        if (!(_getOption(options, "format") in _dict("hex", "byteseq", "base64", "base64_safe"))) {
            if (_isInstance(context, "MD5", "SHA1", "SHA256", "TIGER192")) {
                options.format = "hex";
            } else if (_isInstance(context, "AES256")) {
                options.format = "base64";
            }
        }
        if (!(_getOption(options, "order") in _dict("little", "big"))) {
            if (_isInstance(context, "MD5", "TIGER192", "AES256")) {
                options.order = "little";
            } else if (_isInstance(context, "SHA1", "SHA256")) {
                options.order = "big";
            }
        }
        return options;
    };

    /**
     * Parse arguments and set default options.
     *
     * @param {Object} context
     * @param {Object} args
     * @return {Object}
     *  
     * @exception {gruft.TypeError}
     * 
     * @private
     */
    var _parseOptions = function (context, args) {
        var options = {}, message = null;
        switch (args.length) {
            case 0:
                throw gruft.TypeError("must supply at least one argument <String message>");
            case 1:
                if (typeof(args[0]) === typeof("")) {
                    options = _setDefaultOptions(context, {});
                    message = args[0];
                } else if (typeof(args[0]) === typeof(Object.prototype)) {
                    options = _setDefaultOptions(context, args[0]);
                    message = _getOption(options, "message");
                }
                break;
            case 2: default:
                if (typeof(args[0]) === typeof("") && typeof(args[1]) === typeof(Object.prototype)) {
                    options = _setDefaultOptions(context, args[1]);
                    message = args[0];
                }
                // break;
        }
        if (typeof(message) !== typeof("")) {
            throw gruft.TypeError("must supply at least one argument <String message>");
        } else {
            options.message = message;    
        }
        return options;
    };

    /**
     * Return true if type and value of obj1 and obj2 are identical,
     * otherwise raise an exception with details of the discrepancies.
     * 
     * @param {Object} obj1 
     * @param {Object} obj2 
     * @param {String} message
     * @param {String|Array} interpolation
     * @return {Boolean}
     * 
     * @exception {gruft.AssertionError}
     * 
     * @private
     */
    var _failUnlessEqual = function (obj1, obj2, message, interpolation) {
        if (obj1.constructor === Array && obj2.constructor === Array) {
            if (obj1.length != obj2.length) {
                throw gruft.AssertionError(message + ", <Array obj1> has %2 elements, but <Array obj2> has %3 elements",
                    [interpolation, obj1.length, obj2.length]);
            }
            var elem1, elem2, index = -1;
            while (++index < obj1.length) {
                try {
                    _failUnlessEqual(obj1[index], obj2[index]);
                } catch (e) {
                    throw gruft.AssertionError(message + ", <Array obj1> and <Array obj2> are not equal at index %2: %3 !== %4",
                        [interpolation, index, obj1[index].valueOf(), obj2[index].valueOf()]);
                }
            }
            return true;
        } else if (obj1.constructor in _dict(Number, String) && obj1.constructor === obj2.constructor) {
            if (obj1 !== obj2) {
                throw gruft.AssertionError(message + ", <%2 obj1> is not equal to <%3 obj2>: %4 !== %5",
                    [interpolation, typeof(obj1), typeof(obj2), obj1.valueOf(), obj2.valueOf()]);
            }
            return true;
        } else {
            throw gruft.AssertionError(message + ", <%2 obj1> and <%3 obj2> must be both of type Array, Number or String",
                [interpolation, typeof(obj1), typeof(obj2)]);
        }
    };

    /**
     * Convert a base91-encoded string to an array of 256 unsigned 32-bit words.
     * 
     * The original base91-encoding scheme was designed by Joachim Henke. 
     * Please note that this implementation uses a different code table.
     *
     * @param {String} source
     * @param {String} format ... (optional)
     * @return {Array}
     * 
     * @private
     */
    var _transformBox = function (source, format) {
        format = format || "byteseq";
        if (!_BASE91_DICT["!"]) {
            var index = -1;
            while (++index < 0x5b) {
                _BASE91_DICT[_BASE91_MAP.charAt(index)] = index;
            }
        }
        // TODO: not necessary for MSIE/Opera
        source = source.split("");
        var word, bits = 0, shift = 0, len = source.length, box = new Array((format == "byteseq") ? 0x100 : 0x407), 
            sfc = String.fromCharCode, i = 0, x = -1;
        if (format == "byteseq") { 
            while (++x < 0x100) { box[x] = 0; } x = -1; 
        }            
        while (i < len) {
            word = _BASE91_DICT[source[i++]] + _BASE91_DICT[source[i++]] * 0x5b;
            bits |= word << shift;
            shift += ((word & 0x1fff) > 0x58) ? 0xd : 0xe;
            do {
                if (format == "byteseq") {
                    box[++x >> 2] |= (bits & 0xff) << ((x % 4) << 3);
                    if (x % 4 == 3) {
                        box[x >> 2] = (box[x >> 2] & 1) + ((box[x >> 2] >>> 1) << 1);
                        // box[x >> 2] = (box[x >> 2] & 1) + ((box[x >> 2] >>> 1) * 2);
                    }
                } else {
                    box[++x] = sfc(bits & 0xff);
                }                        
                shift -= 8;
                bits >>= 8;
            } while (shift >> 3);
        }    
        return (format == "byteseq") ? box : box.join("");
    };    

    /**
     * ...
     * 
     * @param {Number} bits
     * @return {Number}
     * 
     * @private
     */
    var _resizeToBase64 = function (bits) {
        var fraction = bits / 6 * 8;
        return ((fraction >> 4) + Math.ceil((fraction - Math.floor(fraction)) * 2)) << 4; 
    };

    /**
     * ...
     * 
     * @private
     */
    var _getRandomSample = function () {
        if (_random === null) {
            _random = _transformBox([
                "a_Y;TC%Tj;J^(5tL;*zByj&d';0qY5[WlBSK<X+('M=,uRdvk}SuCG-vK&_9&!ClX/_QF1>Lbja(VOvAIxX(6pi?ns$2FS$.wy!",
                "*B~_1S=K%ds0{c5K>fw7i9TpT+?oX_]3Xk}Ub}IE;[%O;wUfcSC#IgP.7meZzf>XFb=*dcGh5^)b4mZPKgaVO7@HJu_]pb6=:bS",
                "NGtg|pxZ@#!X-9G82k{a/~npX6<5MQ[[%LQ(1(!&7!'@@@,I1)>^F9e)'i9KZ&=TTRK$2K+5Y9-z><NWFrk&^oMVT{hRi%BKe{&",
                "Ofrt<tgLwd>w*b;bVeSL@7/,skH9l~e{RvOv{54%.K&=:oCL5m&Vh0m/W'$qo1*h(JoQr*;~TQ_IN0p?%TdrHMs{SLRJ!w;6rM!",
                "HG@4*kJ2*D]rzG>Zt1?1<JxXj_XMCOXX'!nTt0.p*/'a?7e8O7zanTAQsm$(^6M;C[n[4oU82e?r6:ui3=mfp>$6_+OnM{BwU]o",
                "5E_N(cdZN!T+3zt</!=u~nY<kvy)]oBp%?<beBM%z)WFNZ2Cv9'@zyvw!z1}E2Q^EIS*9oy2Wa<lcooEKt|wHSKU!6GUK3+'nCA",
                "SL}O##~[ebQuJO.';K4'-nsX661T@TxLr6e,?y#+nN4.=pOkaD%4;!enNnezN9qgsdShO^=|gU'yTWbFkylM6tYmyL_E)tSl1F3",
                "wNhcWwvVGLTF@dA}JvK?y:NT;7eJWGO}Y|s1+'ZY(*=|lk/YH~Y*9j*pgORhl.QiX^:dmQ_}l4QY$G@1Xwz!oNQ=P47#Ux}DD~P",
                "X':!a00S2>GyxH<bf6=4Yn1?lbTD<P'8h%z|Df>,&R1uZ6FzmHl?<!riCU41}K-(z:VSIGhxTfSv!RTJ~tMm@M]of?QrGbL_[V9",
                "jZ%L|t-T~k(uR_[iYL0e28KN%jQ&,(<XkyhKDSi*)?hRNp8EXAj|QrE%WUne}.lO5X%FnYT]kjHW>=g[W}nrcBGLH]4nfHA8dlj",
                "YYs?|y4+4Jm:;w(:{bZsjz+G]6:cPe?>on4%a5mk@k]1PtjQh[n1h1*^DE:GVOWr<c|^s)m<n._5N$ewRn4}69TbX!tU0fesL0q",
                "v3?TT7m;B0-Bv8P4+O2SNv.(sWC+,hQ/{C,H+AR7B<ZZhp9<[l*wWoaDrTFGlh?8[:o+NVwrR3RBsHc(#v8Tlm@,@!}kc]je|rD",
                "T@hVPsSQmK=}!5GUW~8D;VWo?P8'voX-09k@Nb#PV@){Xp:TTUXx,;0^)o+V?],<mpiP(9TR8~JruP6W"
                ].join(""), true);            
        }
        return _random;
    };

    /**
     * ...
     *  
     * @param {Number} len
     * 
     * @private
     */
    var _getRandomString = function (len) {
        var sample = _getRandomSample(), slen = sample.length;
        if (len < slen) {
            return sample.substr(0, len);
        } else if (len === slen) {
            return sample;
        } else {
            for (var c = 0, concat = []; c < len / slen; c++) { concat.push(sample); }
            return concat.join("").substr(0, len);
        }
        
    };

    /**
     * ...
     *
     * @param {String} handle
     * @return {String}
     * 
     * @exception {gruft.RangeError}
     * 
     * @private
     */
    var _getTestvector = function (handle) {
        if (!(handle in _dict("digest-base64", "digest-span-utf8", "digest-span-utf16", "digest-1024x0", "digest-random"))) {
            throw gruft.RangeError("testvector handle %s is not supported", handle);
        } else {
            if (!_testvectors[handle]) {
                var sfc = String.fromCharCode;
                
                /* Basic. */
                _testvectors["digest-base64"] = _BASE64_CHARSET;
                
                /* 24 % 3 == 0. */
                _testvectors["digest-span-utf8"] = sfc(
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x7c, 0x7d, 0x7e, 0x7f, 
                    0x80, 0x81, 0x82, 0x83, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff 
                    );
                _testvectors["digest-span-utf16"] = sfc(
                    0xffff, 0xfffe, 0xfffd, 0xfffc, 0xfffb, 0xfffa, 0xfff9, 0xfff8, 0x8003, 0x8002, 0x8001, 0x8000,  
                    0x7fff, 0x7ffe, 0x7ffd, 0x7ffc, 0x0007, 0x0006, 0x0005, 0x0004, 0x0003, 0x0002, 0x0001, 0x0000 
                    );
                
                /* 1024 % 3 == 1. */                    
                for (var c = 0, vector = new Array(1024), zero = sfc(0); c < 1024; c++) {
                    vector[c] = zero;
                }
                _testvectors["digest-1024x0"] = vector.join("");
               
                /* 1031 % 3 == 2, 1031 is prime. */
                _testvectors["digest-random"] = _getRandomSample();
            }
            return _testvectors[handle];
        }
    };

    /**
     * Clip a UTF-16 string to byte-sized characters.
     *          
     * @param {String} source
     * @return {String}
     * 
     * @private
     */
    var _clipString = function (source) {
        if (source.length === 0) {
            return "";
        } else {
            /* Opera-specific optimization. This does not affect profiling. */
            if (_isDefined(window) && _isDefined(window.opera)) { source = new String(source); }
            
            var len = source.length, output = new Array(len), sfc = String.fromCharCode, c = -1;
            while (++c < len) {
                output[c] = sfc(source.charCodeAt(c) & 0xff);
            }
            return output.join("");
        }
    };

    /**
     * ...
     * 
     * @return {String|Array}
     * 
     * @private
     */
    var _digest = function () {
        /*  Parse arguments and set default options. */
        var options = _parseOptions(this, arguments), message = options.message, format = options.format,
            codepath = this.getCodepath(), id = this.__class__,
            output;

        /* Clock start of computation. */
        var ticks = (new Date()).valueOf();

        var intermediate, pos, encoded, len;

        /* Compute intermediate digest using pure Javascript. */
        var tuple = _singletons[id].__digest__.apply(_singletons[id], [message, options]);

        if (options.order == "little") { 
            var mul = 1, off = 0; 
        } else {
            var mul = -1, off = 3;    
        }
        intermediate = []; pos = -1;
        while (++pos < tuple.length * 4) {
            if (format == "hex") {
                intermediate.push(_BASE16_MAP[tuple[pos >> 2] >> 8 * (off + mul * pos % 4) + 4 & 0xf],
                    _BASE16_MAP[tuple[pos >> 2] >> 8 * (off + mul * pos % 4) & 0xf]);
            } else {
                intermediate.push(tuple[pos >> 2] >> 8 * (off + mul * pos % 4) & 0xff);
            }
        }
        if (format == "hex") { 
            intermediate = intermediate.join(""); 
        } 

        if (format in _dict("base64", "base64_safe")) {
            var map = (format == "base64") ? _BASE64_MAP : _BASE64_MAP_SAFE,
                remainder = intermediate.length % 3;
            encoded = []; pos = 0; len = intermediate.length - remainder;
            while (pos < len) {
                encoded.push(map[intermediate[pos] >> 2], map[(intermediate[pos++] & 0x3) << 4 | intermediate[pos] >> 4],
                    map[(intermediate[pos++] & 0xf) << 2 | intermediate[pos] >> 6], map[intermediate[pos++] & 0x3f]);
            }
            if (remainder == 1) {
                encoded.push(map[intermediate[pos] >> 2], map[(intermediate[pos] & 0x3) << 4]);
                if (format == "base64") { encoded.push(map[64], map[64]); }
            } else if (remainder == 2) {
                encoded.push(map[intermediate[pos] >> 2], map[(intermediate[pos++] & 0x3) << 4 | intermediate[pos] >> 4],
                    map[(intermediate[pos] & 0xf) << 2]);
                if (format == "base64") { encoded.push(map[64]); }
            }
            output = encoded.join("");
        } else {
            output = intermediate;
        }

        /* Sample execution time and rate. */
        if (_isDefined(_addins["gruft.profile"])) {
            _addins["gruft.profile"].sample(this.__signature__, message.length, (new Date()).valueOf() - ticks);
	    }

        return output;
    };

    /**
     * ...
     * 
     * @private
     */
    var _encrypt = function () {
            
    };            

    /**
     * ...
     * 
     * @private
     */
    var _decrypt = function () {
            
    };


    /******************************************************************************************************************
     *  PUBLIC METHODS
     */

    /**
     * ...
     */
    gruft.common = {

        /**
         * ...
         * 
         * @param {Object} context
         * @param {Object} implementation
         * 
         * @exception {gruft.RangeError}
         * @exception {gruft.SyntaxError}
         */
        reflect: function (context, implementation) {
            return _reflect.apply(this, arguments);
        },

        /**
         * Return an iterable object with keys constructed from a supplied argument list, and true-ish values.
         *
         * @return {Object} An iterable object.
         */
        dict: function () {
            return _dict.apply(this, arguments);
        },  

        /**
         * ...
         * 
         * @param {Number} bits
         * @return {Number}
         */
        resizeToBase64: function () {
            return _resizeToBase64.apply(this, arguments);
        },

        /**
         * ...
         * 
         * @param {Number} len
         * @return {String}
         */
        getRandomString: function (len) {
            return _getRandomString.apply(this, arguments);
        },

        /**
         * ...
         * 
         * @param {String} handle
         * @return {String}
         * 
         * @exception {gruft.RangeError}
         */
        getTestvector: function (handle) {
            return _getTestvector.apply(this, arguments);
        },

        /**
         * Return true if type and value of obj1 and obj2 are identical,
         * otherwise raise an exception with details of the discrepancies.
         * 
         * @param {Object} obj1 
         * @param {Object} obj2 
         * @param {String} message
         * @param {String|Array} interpolation
         * @return {Boolean}
         * 
         * @exception {gruft.AssertionError}
         */
        failUnlessEqual: function (obj1, obj2, message, interpolation) {
            return _failUnlessEqual.apply(this, arguments);
        }, 

        /**
         * Clip a UTF-16 string to byte-sized characters.
         *          
         * @param {String} source
         * @return {String}
         */
        clipString: function (source) {
            return _clipString.apply(this, arguments);
        },

        /**
         * Convert a base91-encoded string to an array of 256 unsigned 32-bit words.
         * 
         * The original base91-encoding scheme was designed by Joachim Henke. 
         * Please note that this implementation uses a different code table.
         *
         * @param {String} source
         * @param {String} format ... (optional)
         * @return {Array}
         */
        transformBox: function (source, format) {
            return _transformBox.apply(this, arguments);
        },

        /**
         * Convert an array of 256 32-bit values to a basE91-encoded string.
         * 
         * @param {Array} box
         * @return {String}
         */
        toBase91: function (box) {
            var b = 0, n = 0, v, encoded = new Array(), pos = 0, x = -1,
                map = _BASE91_MAP.split("");
            while (++x < box.length) {
                // b |= ((box[x >> 2] >> 8 * (x % 256)) & 0xff) << n;
                b |= box[x] << n;
                n += 8;
                if (n > 13) {
                    v = b & 0x1fff;
                    if (v > 88) {
                        b >>= 13;
                        n -= 13;
                    } else {
                        v = b & 0x3fff;
                        b >>= 14;
                        n -= 14;
                    }
                    encoded[pos++] = _BASE91_MAP[v % 91]; 
                    encoded[pos++] = _BASE91_MAP[Math.floor(v / 91)];
                }               
            }
            encoded[pos++] = _BASE91_MAP[b % 91]; 
            encoded[pos]   = _BASE91_MAP[Math.floor(b / 91)];
            return encoded.join("");                
        }        

	};
    

    /******************************************************************************************************************
     *  EXCEPTIONS
     */
    
    
    // TODO: gruft.common.getLastException()
    
    // TODO: proper inheritance:
    //         http://ejohn.org/blog/simple-javascript-inheritance/
    
    
    /**
     * ...
     * 
     * @param {Object} code
     * @param {Object} exception
     * 
     * @private
     */
    var Exception = function (code, exception) {
        var error = new Error();
        error.number = code;
        error.name = exception;
        
        /**
         * 
         * @param {String} message
         * @param {String|Array} interpolation
         * @param {String} module
         * @param {Number} line
         */
        return function (message, interpolation, module, line) {
            message = message || "";
            if (message && interpolation) {
                if (interpolation.constructor in _dict(String, Number)) {
                    message = message.replace(/%(s|1)/g, interpolation);    
                } else if (interpolation.constructor === Array) {
                    message = message.replace(new RegExp("%([1-" + interpolation.length + "])", "g"), function (match, offset) {
                        return (offset > interpolation.length) ? match : interpolation[offset - 1];
                    });                    
                }
            }
            error.message = message;
            var qualified = exception;
            if (!!message) { 
                qualified += ": " + message; 
            }
            if (!!module) {
                error.fileName = module;
                qualified += " [" + module;
                if (!!line) {
                    error.lineNumber = line;                    
                    qualified += ":" + line;
                }
                qualified += "]";
            }
            error.toString = function () { return qualified; };
            error.description = qualified;
            return error;
        };
    };

    /* ... */
    var num = 0;
    for (var exception in _dict(_exceptions)) {
        if (/^\w+Error$/.test(exception)) {
            gruft[exception] = new Exception(2 << num++ >> 1, exception);
        }
    }

 
    /******************************************************************************************************************
     *  SETUP
     */
    
 	_setup.apply(this, arguments);    

}(this);
