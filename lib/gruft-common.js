/*!
 *  gruft-common module Version 0.0.8-2009xxyy Copyright (c) 2009 Nikola Klaric.
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
 */

/**
 * @namespace gruft.*
 */
var gruft; if (typeof(gruft) !== typeof(Object.prototype)) { gruft = {}; }

/**
 * ...
 */
new function (scope) {

    var __name__    = "gruft.common",
        __author__  = "Nikola Klaric",
        __version__ = "0.0.8";


    /******************************************************************************************************************
     *  PRIVATE PROPERTIES
     */

    /**
     * ...
     */
    var _exceptions = [
        "TypeError",            /* Raised when a supplied parameter is of wrong type. */ 
        "RangeError",           /* Raised when a supplied parameter value is out of range. */
        "SyntaxError",          /* Raised when an interface in the gruft.* namespace is used incorrectly. */
        "AssertionError",       /* Raised when an assertion fails. */
        "NotImplementedError"   /* Raised when an interface in the gruft.* namespace is used which is not implemented. */
        ];

    /**
     * Collection of instantiated singletons.
     */
    var _singletons = {};

    /**
     * Collection of registered addins (e.g. profiling, XPCOM-support).
     */
    var _addins = {};

    /**
     * Symbol tables for fast conversion.
     */
	var _ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        _ALPHANUM = _ALPHA + _ALPHA.toLowerCase() + "0123456789",
        _BASE16_MAP = "0123456789abcdef".split(""),
        _BASE64_CHARSET = _ALPHANUM + "+/=",
        _BASE64_CHARSET_SAFE = _ALPHANUM + "-_",
        _BASE64_MAP = _BASE64_CHARSET.split(""),
        _BASE64_MAP_SAFE = _BASE64_CHARSET_SAFE.split(""),
        _BASE91_MAP = _ALPHANUM + "!#$%&()*+,./:;<=>?@[]^_'{|}~-",
        _BASE91_DICT = {};


    /******************************************************************************************************************
     *  PRIVATE METHODS
     */
		
	/**
	 * ...
	 */
	var _is = new function (proto, that) {
		var _type = function (object, type) {
			return proto.toString.call(object) === "[object " + type + "]";
		};
		return {
			Object: function (object) { return _type(object, "Object"); },
			Function: function (object) { return _type(object, "Function"); },
			Number: function (object) { return _type(object, "Number"); },
			String: function (object) { return _type(object, "String"); },
			Array: function (object) { return _type(object, "Array"); },
			any: function (object) {
                for (var a = 1, type; type = arguments[a]; a++) {
					if (_type(object, type)) {
						return true;
					}
				}
				return false;
			},
			which: function (object) {
				var _is = that._is;
				for (var type in _is) {
					if (/^[A-Z][a-z]+$/.test(type) && proto.hasOwnProperty.call(_is, type) && _is[type](object)) {
						return type;
					}
				}
				return typeof(object);
			},
			instance: function (object) {
				for (var a = 1, type; type = arguments[a]; a++) {
                    if (type in gruft && object instanceof gruft[type]) {
                        return true;
                    }
                }
                return false;
			}
		};
	}(Object.prototype, this);

    /**
     * Return an iterable object with keys constructed from a supplied argument list, and true-ish values.
     * Make sure that iteration only yields keys from the argument list.
     */
    var _dict = function () {
        var head = arguments[0], keys = (_is.Array(head)) ? head : arguments,
            items = {}, token = "gruft.deadbeef";
        for (var k = 0, name; name = keys[k]; k++) {
            if (name !== null) {
                items[name] = token;   
            }
        }
        for (var key in items) {
            if (items[key] !== token) {
                delete items[key];
            }
        }
        return items;
    };

    /**
     * ...
     */
    /* var _setup = function () {
        _import.apply(this, arguments);
        for (var d = 0, iface; iface = _defered[d]; d++) {
            if (!_isDefined(gruft.common[iface])) {
                gruft.common[iface] = function () {
                    _import();
                    if (!_isDefined(gruft.common[iface].__future__)) {
                        return gruft.common[iface].apply(gruft.common, arguments);
                    }
                };
                gruft.common[iface].__future__ = 1;
            }
        } 
    }; */
    
    /**
     * Search the gruft.* namespace for modules which provide addin facilities, and import them.
     * Only modules declared in the same scope as this module will be imported. 
     */
    var _import = function () {
        // _scope = _scope || arguments.length && arguments[0];
        for (var symbol in gruft) {
            var object = gruft[symbol];
			if (/^__\w+__$/.test(symbol) && _is.Object(object) && "scope" in object 
                    && object.scope === scope && object.scope.gruft === gruft) {
                _addins[object.namespace] = object;
				if (_is.Function(object.extend)) {
					object.extend(gruft.common);
                }
                delete gruft[symbol];
            }
        }
    };

    /**
     * ...
     */
    var _reflect = function (context, implementation) {
        var proto = implementation.prototype, name = proto.__name__, id = /\w+$/.exec(name);
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
                if (field in proto && !(/^__\w+__$/.test(field)) || !!profiler && field in profiler.enumerate()) {
                    context[field] = _singletons[id][field];
                }
            }
            context.__name__ = name;
            context.__class__ = id;
            context.__repr__ = proto.__repr__;
            context.__signature__ = signature;                
            context.getCodepath = function () { return codepath; };

            /* Setup automagical output formatting. */
            if (_is.instance(context, "MD5", "SHA1", "SHA256", "TIGER192")) {
                context.digest = _digest;
                context.__digest__ = function () { return context.digest.apply(context, arguments); };
            } else if (_is.instance(context, "AES256")) {

            }
        }
    };

    /**
     * Return an option from a given arguments list if defined, otherwise null.
     */
    var _getOption = function (args, field) {
        return (!!args && field in args) ? args[field] : null;
    };

    /**
     * Parse arguments and set default options.
     *  
     * @exception {gruft.TypeError}
     */
    var _parseOptions = function (context, args) {
        var options = {}, message = null;
        switch (args.length) {
            case 0:
                throw gruft.TypeError("must supply at least one argument <String message>");
            case 1:
                if (_is.String(args[0])) {
                    options = _setDefaultOptions(context, {});
                    message = args[0];
                } else if (_is.Object(args[0])) {
                    options = _setDefaultOptions(context, args[0]);
                    message = _getOption(options, "message");
                }
                break;
            case 2: default:
                if (_is.String(args[0]) && _is.Object(args[1])) {
                    options = _setDefaultOptions(context, args[1]);
                    message = args[0];
                }
        }
        if (!_is.String(message)) {
            throw gruft.TypeError("must supply at least one argument <String message>");
        } else {
            options.message = message;    
        }
        return options;
    };

    /**
     * Set default options for digest and encryption implementations.
     */
    var _setDefaultOptions = function (context, options) {
        if (!(_getOption(options, "format") in _dict("hex", "byteseq", "base64", "base64_safe"))) {
            if (_is.instance(context, "MD5", "SHA1", "SHA256", "TIGER192")) {
                options.format = "hex";
            } else if (_is.instance(context, "AES256")) {
                options.format = "base64";
            }
        }
        if (!(_getOption(options, "order") in _dict("little", "big"))) {
            if (_is.instance(context, "MD5", "TIGER192", "AES256")) {
                options.order = "little";
            } else if (_is.instance(context, "SHA1", "SHA256")) {
                options.order = "big";
            }
        }
        return options;
    };
	
    /**
     * Return true if type and value of obj1 and obj2 are identical,
     * otherwise raise an exception with details of the discrepancies.
     * 
     * @exception {gruft.AssertionError}
     */
    var _failUnlessEqual = function (obj1, obj2, message, interpolation) {
        if (_is.Array(obj1) && _is.Array(obj2)) {
            if (obj1.length != obj2.length) {
                throw gruft.AssertionError(message + ", <Array obj1> has %2 elements, but <Array obj2> has %3 elements",
                    [interpolation, obj1.length, obj2.length]);
            }
			for (var index = 0; index < obj1.length; index++) {
                try {
                    _failUnlessEqual(obj1[index], obj2[index]);
                } catch (e) {
                    throw gruft.AssertionError(message + ", <Array obj1> and <Array obj2> are not equal at index %2: %3 !== %4",
                        [interpolation, index, obj1[index].valueOf(), obj2[index].valueOf()]);
                }
            }
            return true;
        } else if (_is.any(obj1, "Number", "String") && _is.any(obj2, "Number", "String")) {
            if (obj1 !== obj2) {
                throw gruft.AssertionError(message + ", <%2 obj1> is not equal to <%3 obj2>: %4 !== %5",
                    [interpolation, _is.which(obj1), _is.which(obj2), obj1.valueOf(), obj2.valueOf()]);
            }
            return true;
        } else {
            throw gruft.AssertionError(message + ", <%2 obj1> and <%3 obj2> must be both of type Array, Number or String",
                [interpolation, _is.which(obj1), _is.which(obj2)]);
        }
    };

    /**
     * Convert a base91-encoded string to an array of 256 unsigned 32-bit words.
     */
    var _transformBox = new function (source, format) {
        var _nosplit = false;
        try { _nosplit = ("gruft")[0]; } catch(e) { };
        
        var _map = {}, index = 0x5a;
        do { _map[_BASE91_MAP.charAt(index)] = index; } while (index--); 

        return function (source, format) {
            if (!_nosplit) source = source.split("");
            format = format || "byteseq";
                        
            var word, bits = 0, shift = 0, len = source.length, i = 0, x = -1;
            if (format == "byteseq") { 
                var box = new Array(0x100), j = 0xff;
                do { box[j] = 0; } while (j--);
            } else {
                var box = new Array(0x407);
            }
            
            while (i < len) {
                word = _map[source[i++]] + _map[source[i++]] * 0x5b;
                bits |= word << shift;
                shift += ((word & 0x1fff) > 0x58) ? 0xd : 0xe;
                do {
                    if (format == "byteseq") {
                        box[++x >> 2] |= (bits & 0xff) << ((x % 4) << 3);
                        if (x % 4 == 3) {
                            box[x >> 2] = (box[x >> 2] & 1) + ((box[x >> 2] >>> 1) << 1);
                        }
                    } else {
                        box[++x] = bits & 0xff;
                    }                        
                    shift -= 8;
                    bits >>= 8;
                } while (shift >> 3);
            }    
            
            return (format == "byteseq") ? box : String.fromCharCode.apply(String, box);
        }
    };    

    /**
     * Calculate size of base64 string required to represent the given input bitfield.
     */
    var _resizeToBase64 = new function () {
		var _buffer = {};
		return function (bits) {
			if (!(bits in _buffer)) {
				var fraction = bits / 6 * 8;
				buffer[bits] = ((fraction >> 4) + Math.ceil((fraction - fraction >> 0.5) * 2)) << 4;
			}
			return buffer[bits];
		} 
    };

    /**
     * ...
     */
    var _getRandomSample = new function () {
		var _random = null;
		return function () {
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
		}
    };

    /**
     * ...
     */
	// TODO: keep longest string in buffer
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
    var _getTestvector = new function () {
		var _vectors = {};
		return function (handle) {
	        if (!(handle in _dict("digest-base64", "digest-span-utf8", "digest-span-utf16", "digest-1024x0", "digest-random"))) {
	            throw gruft.RangeError("testvector handle %s is not supported", handle);
	        } else {
	            if (!_vectors[handle]) {
	                var sfc = String.fromCharCode;
	                
	                /* Basic. */
	                _vectors["digest-base64"] = _BASE64_CHARSET;
	                
	                /* 24 % 3 == 0. */
	                _vectors["digest-span-utf8"] = sfc(
	                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x7c, 0x7d, 0x7e, 0x7f, 
	                    0x80, 0x81, 0x82, 0x83, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff 
	                    );
	                _vectors["digest-span-utf16"] = sfc(
	                    0xffff, 0xfffe, 0xfffd, 0xfffc, 0xfffb, 0xfffa, 0xfff9, 0xfff8, 0x8003, 0x8002, 0x8001, 0x8000,  
	                    0x7fff, 0x7ffe, 0x7ffd, 0x7ffc, 0x0007, 0x0006, 0x0005, 0x0004, 0x0003, 0x0002, 0x0001, 0x0000 
	                    );
	                
	                /* 1024 % 3 == 1. */                    
	                for (var c = 0, vector = new Array(1024), zero = sfc(0); c < 1024; c++) {
	                    vector[c] = zero;
	                }
	                _vectors["digest-1024x0"] = vector.join("");
	               
	                /* 1031 % 3 == 2, 1031 is prime. */
	                _vectors["digest-random"] = _getRandomSample();
	            }
	            return _vectors[handle];
	        }
		}
    };

    /**
     * Clip a UTF-16 string to byte-sized characters.
     */
    var _clipString = function (source) {
        if (source.length === 0) {
            return "";
        } else {
            /* Opera-specific optimization. This does not affect profiling. */
            // if (_isDefined(window) && _isDefined(window.opera)) { source = new String(source); }
            
			// TODO: optimize this
            var len = source.length - 1, output = new Array(len + 1);
			do {
				output[len] = source.charCodeAt(len) & 0xff;
            } while (len--);
			output = String.fromCharCode.apply(String, output);
            return output;
        }
    };

    /**
     * ...
     */
    var _digest = function () {
        /*  Parse arguments and set default options. */
        var options = _parseOptions(this, arguments), message = options.message, format = options.format,
            codepath = this.getCodepath(), id = this.__class__,
            output;

        /* Clock start of computation. */
        var ticks = (new Date()).valueOf();

        var buffer, pos, encoded, len;

        /* Compute intermediate digest. */
        var tuple = _singletons[id].__digest__.apply(_singletons[id], [message, options]);

        if (options.order == "little") { 
            var factor = 1, offset = 0; 
        } else {
            var factor = -1, offset = 3;    
        }
        buffer = []; pos = -1;
        while (++pos < tuple.length * 4) {
            if (format == "hex") {
                buffer.push(_BASE16_MAP[tuple[pos >> 2] >> 8 * (offset + factor * pos % 4) + 4 & 0xf],
                    _BASE16_MAP[tuple[pos >> 2] >> 8 * (offset + factor * pos % 4) & 0xf]);
            } else {
                buffer.push(tuple[pos >> 2] >> 8 * (offset + factor * pos % 4) & 0xff);
            }
        }
        if (format == "hex") { 
            buffer = buffer.join(""); 
        } 

        if (format in _dict("base64", "base64_safe")) {
            var map = (format == "base64") ? _BASE64_MAP : _BASE64_MAP_SAFE,
                remainder = buffer.length % 3;
            encoded = []; pos = 0; len = buffer.length - remainder;
            while (pos < len) {
                encoded.push(map[buffer[pos] >> 2], map[(buffer[pos++] & 0x3) << 4 | buffer[pos] >> 4],
                    map[(buffer[pos++] & 0xf) << 2 | buffer[pos] >> 6], map[buffer[pos++] & 0x3f]);
            }
            if (remainder == 1) {
                encoded.push(map[buffer[pos] >> 2], map[(buffer[pos] & 0x3) << 4]);
                if (format == "base64") { encoded.push(map[64], map[64]); }
            } else if (remainder == 2) {
                encoded.push(map[buffer[pos] >> 2], map[(buffer[pos++] & 0x3) << 4 | buffer[pos] >> 4],
                    map[(buffer[pos] & 0xf) << 2]);
                if (format == "base64") { encoded.push(map[64]); }
            }
            output = encoded.join("");
        } else {
            output = buffer;
        }

        /* Sample execution time and rate. */
        if ("gruft.profile" in _addins) {
            _addins["gruft.profile"].sample(this.__signature__, message.length, (new Date()).valueOf() - ticks);
	    }

        return output;
    };

    /**
     * ...
     */
    var _encrypt = function () {
            
    };            

    /**
     * ...
     */
    var _decrypt = function () {
            
    };


    /******************************************************************************************************************
     *  PUBLIC METHODS
     */

    gruft.common = {

        /**
         * ...
         */
        reflect: function (context, implementation) {
            return _reflect.apply(this, arguments);
        },

        /**
         * Return an iterable object with keys constructed from a supplied argument list, and true-ish values.
         */
        dict: function () {
            return _dict.apply(this, arguments);
        },  

        /**
         * ...
         */
        resizeToBase64: function () {
            return _resizeToBase64.apply(this, arguments);
        },

        /**
         * ...
         */
        getRandomString: function (len) {
            return _getRandomString.apply(this, arguments);
        },

        /**
         * ...
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
         * @exception {gruft.AssertionError}
         */
        failUnlessEqual: function (obj1, obj2, message, interpolation) {
            return _failUnlessEqual.apply(this, arguments);
        }, 

        /**
         * Clip a UTF-16 string to byte-sized characters.
         */
        clipString: function (source) {
            return _clipString.apply(this, arguments);
        },

        /**
         * Transform a base91-encoded string to an array of 256 unsigned 32-bit words.
         */
        transformBox: function (source, format) {
            return _transformBox.apply(this, arguments);
        },

        /**
         * Convert an array of 256 32-bit values to a basE91-encoded string.
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
    
	var factory = (function() {
		function F() {};
		return function(p) {
      		F.prototype = p;
			return new F();
		};
	})();
    
    /**
     * ...
     */
    var Exception = function (code, exception) {
        var error = new Error();
		error.prototype = Error;
        error.number = code;
        error.name = exception;
		
        /**
         * ...
         */
        return function (message, interpolation, module, line) {
            message = message || "";
            if (message && interpolation) {
                if (_is.any(interpolation, "String", "Number")) {
                    message = message.replace(/%(s|1)/g, interpolation);    
                } else if (_is.Array(interpolation)) {
					if (~message.indexOf("%s") && !~message.indexOf("%1")) message = message.replace("%s", "%1");
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
    
 	// _setup.apply(this, arguments);  
	_import.apply(this, arguments);    

}(this);
