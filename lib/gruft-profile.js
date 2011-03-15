/*!
 *  gruft-profile module Version 0.0.8-2009xxyy Copyright (c) 2009 Nikola Klaric.
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
 *  var tDistribution = 2.776; -> 5 runs

 *  
 *  function compute(times, runs){
  var num = times.length, results = {runs: num};
 
  times = times.sort(function(a,b){
    return a - b;
  });
 
  // Make Sum
  results.sum = 0;
 
  for ( var i = 0; i < num; i++ )
    results.sum += times[i];
 
  // Make Min
  results.min = times[0];
      
  // Make Max
  results.max = times[ num - 1 ];

  // Make Mean
  results.mean = results.sum / num;

  var log = 0;

  for ( var i = 0; i < num; i++ ) {
    log += Math.log(times[i]);
  }

  results.geometric_mean = Math.pow(Math.E, log / num);
  
  // Make Median
  results.median = num % 2 == 0 ?
    (times[Math.floor(num/2)] + times[Math.ceil(num/2)]) / 2 :
    times[Math.round(num/2)];
  
  // Make Variance
  results.variance = 0;

  for ( var i = 0; i < num; i++ )
    results.variance += Math.pow(times[i] - results.mean, 2);

  results.variance /= num - 1;
      
  // Make Standard Deviation
  results.deviation = Math.sqrt( results.variance );

  // Compute Standard Errors Mean
  results.sem = (results.deviation / Math.sqrt(results.runs)) * tDistribution;   -> SEM

  // Error
  results.error = ((results.sem / results.mean) * 100) || 0;

  return results;
}

 *  
 *  
 *  
 */

/**
 * @namespace gruft.*
 */
var gruft; if (typeof(gruft) !== typeof({})) { gruft = {}; }

/**
 * ...
 */
// new function (global) {
gruft.dummy = function (global) {

    var __name__    = "gruft.profile", 
        __author__  = "Nikola Klaric", 
        __version__ = "0.0.8";

    /******************************************************************************************************************
     *  PRIVATE PROPERTIES
     */

    /**
     * 
     */
	var isMSIE = !+"\v1";	

    /**
     * consider:
     * typeof document.body.style.maxHeight === "undefined"
     */
    var isMSIE6 = isMSIE && !window.XMLHttpRequest;
    
    // Object.prototype.toString.call(window.opera) === "[object Opera]";

    
    /**
     * move this to renderSkeleton() and use container.ownerDocument
     */
    var isStrict = document.compatMode == "CSS1Compat";


    var DELAY = 0;
    var DIAGRAM_CANVAS_HEIGHT = 200;
    var SCALE_RATE = 14000, SCALE_TIME = 600;
    
    var _samplesRandom;

    var diagramHooks = {};
    
    var readoutNodes = {};

    var sliderNodes = {};

    /**
     * 
     */
    var buffer = {
        rate: new Array(4),
        time: new Array(4)
    };

    /**
     * 
     */
    var previousValue = {
        rate: [null, null, null, null],
        time: [null, null, null, null]
        };

    /**
     * 
     */
    var fractions = {
        rate: [0, 0, 0, 0],
        time: [0, 0, 0, 0]
        };


    var round = 0, sample = 0, algos = [], current = 0, counter = 0;
    
    /**
     * ...
     *
     * @type {Array}
     * @private
     */
    var _methods = [
        "resetRates", "getMinRate", "getMaxRate", "getMeanRate", "getStdevRates", "getMedianRate", "getLastRate", "getLastRateValue", 
        "resetTimes", "getMinTime", "getMaxTime", "getMeanTime", "getStdevTimes", "getMedianTime", "getLastTime", "getLastTimeValue"
        ]; 

    /**
     * ...
     *
     * @type {Object}
     * @private
     */
    var _rates = {}; 
    
    /**
     * ...
     *
     * @type {Object}
     * @private
     */
    var _times = {}; 
    
    /**
     * ...
     *
     * @type {Number}
     * @private
     */
    var _last = {}; 
	
    /******************************************************************************************************************
     *  PRIVATE METHODS
     */

    /**
     * ...
     *
     * @return {Object}
     *
     * @private
     */
    var _dict = function () {
        return gruft.common.dict.apply(this, arguments);
    }; 
    
    /**
     * ...
     *
     * @param {Object} functor
     * @param {Object} context
     * @param {String} method
     * @param {String} signature
     * @return {Function}
     *
     * @private
     */
    var _bind = function (functor, context, method, signature) {
        var slice = Array.prototype.slice;
        return function () {
            return functor.apply(context, [method, signature].concat(
				slice.apply(arguments, slice.call(
					arguments, 4))
				)
			);
        };
    }; 

    /**
     * ...
     */
    var _enumerate = function () {
        return _dict(_methods);
    }; 
    
    /**
     * ...
     */
    var _decorate = function (target, context, signature) {
        for (var method in _enumerate()) {
            target[method] = _bind(_implement, context, method, signature);
        }
    }; 
    
    /**
     * ...
     */
    var _implement = function (method, signature, base) {
        var isRateMethod = /Rate/.test(method), isValueReq = /Value$/.test(method), 
            samples = (isRateMethod) ? _rates[signature] : _times[signature];
        if (!samples || samples.length === 0) {
            return "n/a";
        } else if (method == "resetRates") {
	        _rates[signature] = [];
	    } else if (method == "resetTimes") {
            _times[signature] = [];
	    } else {
            var len = samples.length;
            base = (isRateMethod) ? (+base != 1000) ? 1024 : 1000 : 1;
            if (len == 1 && !(/Stdev/.test(method))) {
                return (isRateMethod) ? _formatRate(samples[0], base, isValueReq) : _formatTime(_last[signature], isValueReq);
            } else if (/^getLastRate/.test(method)) {
	            return _formatRate(samples[len - 1], base, isValueReq);
	        } else if (/^getLastTime/.test(method)) {
	            return (!_last[signature]) ? "n/a" : _formatTime(_last[signature], isValueReq);
            } else if (method in _dict("getMeanRate", "getMeanTime", "getStdevRates", "getStdevTimes")) {
                var sum = 0, c = -1;
                while (++c < len) {
                    sum += samples[c];
                }
                var mean = sum / len;
                if (method in _dict("getMeanRate", "getMeanTime")) {
                    return (mean < 1) ? "inf." : (isRateMethod) ? _formatRate(mean, base) : _formatTime(mean);
                } else if (method in _dict("getStdevRates", "getStdevTimes")) {
                    var stdev = 0;
                    if (len > 1) {
                        var devsq = 0, d = -1;
                        while (++d < len) {
                            devsq += Math.pow((samples[d] - mean) / base, 2);
                        }
                        stdev = Math.round(Math.sqrt(devsq / (len - 1)));
                    }
                    return stdev;
                }
            } else {
                var samplesCopy = samples.concat(), data;
                /// TODO: sort after insertion, not here
                /*  The builtin Array.prototype.sort() won't compare our sample elements correctly in some engines. */
                var _cmpRate = function(a, b){
                    return a - b;
                };
                samplesCopy.sort(_cmpRate);
                if (method in _dict("getMedianRate", "getMedianTime")) {
                    if (len % 2) {
                        data = samplesCopy[len >>> 1];
                    } else {
                        data = (samplesCopy[len / 2 - 1] + samplesCopy[len / 2]) / 2;
                    }
                } else if (method in _dict("getMinRate", "getMinTime")) {
                    data = samplesCopy[0];
                } else if (method in _dict("getMaxRate", "getMaxTime")) {
                    data = samplesCopy[len - 1];
	            } else {
                    /* This must never be raised. */
                    throw gruft.RangeError("method %s is not supported", method);
	            }
                return (isRateMethod) ? _formatRate(data, base) : _formatTime(data);
	        }
	    }
    }; 
    
    /**
     * ...
     *
     * @param {Number} value
     * @param {Number} base
     * @param {Boolean} raw
     * @return {String|Number}
     *
     * @private
     */
    var _formatRate = function (value, base, raw) {
        return Math.round(value / base) + ((!raw) ? ((base == 1024) ? " Kbps" : " kbps") : 0);
    }; 
    
    /**
     * ...
     *
     * @param {Number} value
     * @param {Boolean} raw
     * @return {String}
     *
     * @private
     */
    var _formatTime = function (value, raw) {
        return Math.round(value) + ((!raw) ? " ms" : 0);
    }; 
    
    /**
     * Sample execution time and rate, but discard rates that ran faster than 20 ms.
     *
     * @param {String} signature
     * @param {Number} size
     * @param {Number} msec
     *
     * @private
     */
    var _sample = function (signature, size, msec) {
        msec = msec || 1;
        if (!_times[signature]) {
            _times[signature] = [];
        }
        _times[signature].push(msec);
        _last[signature] = msec;
        if (msec >= 20) {
            if (!_rates[signature]) {
                _rates[signature] = [];
            }
            _rates[signature].push((size || 1) * 8 * 1000 / msec);
        }
    }; 
    
    /**
     *
     */
    var _extend = function (context) {
        context.profile = _profile;
    }; 
    
    /**
     *
     */
    var _profile = function (container) {
        _build(container);
        algos[0] = arguments[1];
        algos[1] = arguments[2];
        algos[2] = arguments[3];
        algos[3] = arguments[4];

        _samplesRandom = [
            gruft.common.getRandomString(19997),
            gruft.common.getRandomString(59951),
            gruft.common.getRandomString(89963),
            gruft.common.getRandomString(39937),
            gruft.common.getRandomString(79987),
            gruft.common.getRandomString(9973),
            gruft.common.getRandomString(99991),
            gruft.common.getRandomString(29959),
            gruft.common.getRandomString(69997),
            gruft.common.getRandomString(49999)
            ];
            
        _step();
    }; 
    
    /**
     * ...
     *
     * @param {Object} container
     */
    var _build_old = function (parent) {
        var metrics = ["Rate", "Time"];
        var samples = ["Min", "Max", "Mean (SD)", "Median"];
        var probes = [{md5: "MD5"}, {sha1: "SHA-1"}, {sha256: "SHA-256"}, {tiger192: "TIGER/192"}, {aes256enc: "AES-256 (encrypt)"}, {aes256dec: "AES-256 (decrypt)"}];
        var numPanels = metrics.length;
        
        /* Calculate segment dimensions. */
        var widgetWidth = 1000, widgetHeight = 160 + probes.length * 24, widgetPadding = 4;
        var diagramInnerWidth = 400, diagramInnerHeight = 100;
        var cellHeight = 24;
        var panelWidth = diagramInnerWidth + 4;
        var liquidColumnWidth = widgetWidth - widgetPadding - panelWidth * numPanels - 6;

        /* Shortcut. */
        var STYLE = "style";
        
        /* CSS values. */
        var _left = "left", _center = "center", _relative = "relative",
            _px = "px", _1px = "1px", _2px = "2px", _3px = "3px", _11px = "11px", _12px = "12px", _1px_solid = _1px + " solid ";
        
        /* Element creation helper. */
       // TODO: doc = doc.ownerDocument || doc.getOwnerDocument && doc.getOwnerDocument() || doc;
        var factory = parent.ownerDocument || parent.getOwnerDocument && parent.getOwnerDocument(),
            createChild = function (mother, id, css, content) {
            var element = factory.createElement("div"), text = [];
            for (var property in css) text.push(property.replace(/([A-Z])/, "-$1").toLowerCase() + ":" + css[property]);
            element.style.cssText = text.join(";").replace("style-", "");
            if (mother) { mother.appendChild(element); }
            if (id) { element.id = id; }
            if (content) { element.appendChild(factory.createTextNode(content)); }
            return element;
        };
        
        /* Use absolute pixel values. */
        var _ = function (value) {
            return (value) + _px;
        };
        
        /* Create widget. */
        var elementProfile = createChild(0, 0, {
            width:           _(widgetWidth - widgetPadding - 2),
            height:          _(widgetHeight - widgetPadding - 2),
            paddingTop:      _(widgetPadding),
            paddingLeft:     _(widgetPadding),
            border:          _1px_solid + "#a7a37e",
            fontFamily:      "Consolas, 'Lucida Console', 'Courier New', Courier, monospace",
            fontSize:        _12px,
            textAlign:       _center,
            backgroundColor: "#e6e2af"
            } );
        if (!isMSIE) {
			// TODO: this is not necessarily faster! think about it:
			// http://ejohn.org/blog/dom-documentfragments/
            var container = factory.createDocumentFragment();
            container.appendChild(elementProfile);
        } else {
            parent.appendChild(elementProfile);    
        }            
        
        /* ... */
        var elementProgress = createChild(elementProfile, 0, {
            styleFloat:      _left,
            width:           _(liquidColumnWidth),
            height:          _(cellHeight * 2 - 2),
            marginRight:     _2px,
            marginBottom:    _2px,
            textAlign:       _left,
            backgroundColor: "#a7a37e"
            } );
        
        var elementProgressText = createChild(elementProgress, "progress-text", {
            position:        _relative,
            left:            _1px,
            width:           _(liquidColumnWidth - 3),
            lineHeight:      _(cellHeight * 2 - 4),
            zIndex:          1001,
            color:           "#fff",
            textAlign:       _center        
            }, "0.0%" );

        var elementProgressBar = createChild(elementProgress, "progress-bar", {
            width:           0,
            height:          _(cellHeight * 2 - 2),
            fontSize:        0,
            zIndex:          1000,
            backgroundColor: "#046380",
            marginTop:       _(-cellHeight * 2 + 4)        
            } );
        
        /* ... */
        var elementHeader = createChild(elementProfile, 0, {
            styleFloat:      _left,        
            width:           _(panelWidth * numPanels),
            height:          _(cellHeight * 2 - 2),
            paddingBottom:   _2px,
            color:           "#000"
            } );
        
        for (var m = 0; m < metrics.length; m++) {
            var elementHeaderMeasure = createChild(elementHeader, 0, {
                styleFloat:      _left,            
                width:           _(panelWidth - 2),
                lineHeight:      _(cellHeight - 2),
                marginRight:     _2px,
                marginBottom:    _2px,
                backgroundColor: "#a7a37e"
                }, metrics[m]);
        }
        
        for (var m = 0; m < metrics.length; m++) {
            for (var s = 0; s < samples.length; s++) {
                var elementHeaderSample = createChild(elementHeader, 0, {
                    styleFloat:      _left,                
                    width:           _(panelWidth / 4 - 2),
                    lineHeight:      _(cellHeight - 2),
                    marginRight:     _2px,
                    backgroundColor: "#a7a37e"                
                    }, samples[s]);
            }
        }
        
        /* ... */
        for (var p = 0; p < probes.length; p++) {
            var elementModule = createChild(elementProfile, 0, {
                styleFloat:      _left,            
                width:           _(liquidColumnWidth - 3),
                lineHeight:      _(cellHeight - 2),
                paddingLeft:     _3px,
                marginRight:     _2px,
                marginBottom:    _2px,
                color:           "#000",
                backgroundColor: "#a7a37e",
                textAlign:       _left         
                } );
            for (var label in probes[p]) {
                elementModule.appendChild(document.createTextNode(probes[p][label]));
                var prefix = label;
            }
            
            for (var m = 0; m < metrics.length; m++) {
                for (var s = 0; s < samples.length; s++) {
                    var id = prefix + "-" + metrics[m].toLowerCase() + "-" + samples[s].split(" ")[0].toLowerCase();
                    var elementSample = createChild(elementProfile, id, {
                        styleFloat:      _left,                    
                        width:           _(panelWidth / 4 - 4),
                        lineHeight:      _(cellHeight - 4),
                        fontSize:        _11px,
                        marginRight:     _2px,
                        marginBottom:    _2px,
                        color:           "#fff",
                        backgroundColor: "#046380",
                        border:          _1px_solid + "#046380",
                        cursor:          "pointer"                   
                        }, "n/a");
                    elementSample.title = "Click to highlight this readout in the diagram below"
                    readoutNodes[id] = elementSample;
                    
                    /* addEvent(elementSample, "click", function (event) {
                        event.srcElement[STYLE].color = "#000";
                        event.srcElement[STYLE].backgroundColor = "#fff";
                        event.srcElement[STYLE].borderColor = "#a7a37e";
                    }); */
                }
            }
        }
        
        var elementSpacer = createChild(elementProfile, 0, {
            styleFloat:      _left,        
            width:           _(liquidColumnWidth),
            height:          _(diagramInnerHeight),
            marginRight:     _2px       
            } );
        
        for (var m = 0; m < metrics.length; m++) {
            var elementDiagramContainer = createChild(elementProfile, "diagram-container-" + metrics[m], {
                styleFloat:  _left,            
                cursor:      "crosshair",
                width:       _(diagramInnerWidth),
                height:      _(diagramInnerHeight),
                marginRight: _2px,
                border:      _1px_solid + "#a7a37e",
                zIndex:      998
                /* background-color: #efecca; */
                });

            var elementDiagramSlider = createChild(elementDiagramContainer, 0, {
                styleFloat:      _left,            
                width:           _1px,
                height:          _(diagramInnerHeight - 2),
                backgroundColor: "#a7a37e",
                fontSize:        0,
                margin:          0,
                marginTop:       _1px,
                borderLeft:      "0px solid #e6e2af",
                zIndex:          999,
                visibility:      "hidden"
                } );
            sliderNodes[metrics[m]] = elementDiagramSlider;

            for (var s = 0; s < samples.length; s++) {
                var elementDiagramCanvas = createChild(elementDiagramContainer, 0, {
                    styleFloat:  _left,                
                    position:    _relative,
                    width:       _(diagramInnerWidth),
                    height:      _(diagramInnerHeight),
                    marginTop:   _(-diagramInnerHeight),
                    zIndex:      1003 - s                                    
                    } );
                diagramHooks["diagram-" + metrics[m].toLowerCase() + "-" + s] = elementDiagramCanvas;
            }

            /* Add events. */
            addEvent(elementProfile, "mousemove", _control);            
            addEvent(elementProfile, "mouseout", _control);
        }
        
        if (!isMSIE) {
            parent.appendChild(container);    
        }
    }; 

    var _build = function (parent) {
        // diagramHooks["diagram-" + metrics[m].toLowerCase() + "-" + s] = elementDiagramCanvas;
    };

    /**
     * MVC controller for event bubble handling
     */
    var _control = function (event) {
        return;
        
        var context = event.target || event.srcElement;
        if (_identify(context, "diagram-container-")) {
            if (event.type == "mousemove") {
                var state = 1;
                // TODO: fix this in Opera, slider disappears over sparklines
                if (parseInt(context.currentStyle.width) == 1) {
                    sliderNodes["Time"].style.borderLeftWidth = parseInt(context.offsetLeft) + "px";
                } else if (event.offsetX > -1 && event.offsetX < 400 && event.offsetY > -1 && event.offsetY < 100) {
                    sliderNodes["Time"].style.borderLeftWidth = parseInt(event.offsetX) + "px";
                } else {
                    state = 0;
                }
                sliderNodes["Time"].style.visibility = ["hidden", "visible"][state];
            } else if (event.type == "mouseout") {
                sliderNodes["Time"].style.visibility = "hidden";
            }
        }
    };

    /**
     * ...
     * 
     * @param {Object} node
     * @param {Object} fragment
     */
    var _identify = function (node, fragment) {
        return !(node.id.indexOf(fragment) && node.parentNode.id.indexOf(fragment));
    };

    /**
     * 
     */    
    var _update = function (){
        var currentRate = algos[counter % 4].getLastRateValue(),
            previousRate = previousValue.rate[counter % 4] || currentRate,
            currentTime = algos[counter % 4].getLastTimeValue(),
            previousTime = previousValue.time[counter % 4] || currentTime;
        
        document.getElementById("gruft-progress-bar").style.width = Math.round((counter + 1) / 480 * 150) + "px";
        var p = (Math.round((counter + 1) / 480 * 150 * 10) / 10).toString();
        if (p.indexOf(".") == -1) 
            p += ".0";
        document.getElementById("gruft-progress-text").innerHTML = p + "%";
        
        /* ... */
        buffer.rate[counter % 4] = _getSegmentBuffer(previousRate, currentRate, SCALE_RATE);
        buffer.time[counter % 4] = _getSegmentBuffer(previousTime, currentTime, SCALE_TIME);
        
        /* ... */
        previousValue.rate[counter % 4] = currentRate;
        previousValue.time[counter % 4] = currentTime;
        
        for (var i = 0; i < 4; i++) {
            if (counter >= i) {
                _renderSegment("rate", i);
                _renderSegment("time", i);
            }
        }
        
        var metrics = ["Rate", "Time"];
        var samples = ["Min", "Max", "Mean (SD)", "Median"];
        var probes = [{md5: "MD5"}, {sha1: "SHA-1"}, {sha256: "SHA-256"}, {tiger192: "TIGER/192"}];

        var p = counter % 4;
        for (var label in probes[p]) {
            var prefix = label;
        }
        for (var m = 0; m < metrics.length; m++) {
            for (var s = 0; s < samples.length; s++) {
                var id = prefix + "-" + metrics[m].toLowerCase() + "-" + samples[s].split(" ")[0].toLowerCase();
                // readoutNodes[id].innerHTML = algos[p]["get" + samples[s].split(" ")[0] + metrics[m]]();
                document.getElementById(id).innerHTML = algos[p]["get" + samples[s].split(" ")[0] + metrics[m]]();
            }
        }
                
    };


    /**
     * 
     * @param {Object} type
     * @param {Object} measure
     */
    var _renderSegment = function (type, measure) {
        var fraction = fractions[type][measure], record = buffer[type][measure], height = record.heights[fraction];
        
        var sparkElement = document.createElement("div");
        sparkElement.style.cssText = [
            "float:left;width:1px;font-size:0;line-height:0",
            "background-color:" + ["#D8A554", "#465D5F", "#831111", "#5B8261"][measure],
            "margin-top:"       + record.margins[fraction] + "px",
            "height:"           + ((height < 2) ? "2px" : height + "px")        
            ].join(";");
            // console.log("diagram-" + type + "-" + measure);
        document.getElementById("diagram-" + type + "-" + measure).appendChild(sparkElement);
        // diagramHooks["diagram-" + type + "-" + measure].appendChild(sparkElement);
	    /* Only for MSIE 6. */
        if (isMSIE6) {
            sparkElement.appendChild(document.createTextNode("."));
        }
        fractions[type][measure] = (fraction + 1) % 4;
    }

    /**
     * 
     * @param {Object} u
     * @param {Object} v
     * @param {Object} scale
     */
    var _getSegmentBuffer = function (u, v, scale) {
        var height = new Array(4), margin = new Array(4), slack;     
        var a = Math.round(u / scale * DIAGRAM_CANVAS_HEIGHT);
        var b = Math.round(v / scale * DIAGRAM_CANVAS_HEIGHT);
        var delta = Math.abs(a - b);
        
        switch (delta) {
            // TODO
        }
        
        height[0] = height[1] = height[2] = height[3] = delta >> 2;
        slack = delta % 4;
        if (slack == 1) {
            height[1] += 1;
        } else if (slack == 2) {
            height[0] += 1;
            height[2] += 1;
        } else if (slack == 3) {
            height[0] += 1;
            height[1] += 1;
            height[3] += 1;
        }
    
        margin[0] = DIAGRAM_CANVAS_HEIGHT - a;
        if (b > a) {
            margin[0] -= height[0];
            margin[1] = margin[0] - height[1];
            margin[2] = margin[1] - height[2];
            margin[3] = margin[2] - height[3];
        } else {
            margin[1] = margin[0] + height[0];
            margin[2] = margin[1] + height[1];
            margin[3] = margin[2] + height[2];
        }    
        return {heights: height, margins: margin};
    };

    /**
     * 
     */
    var _step = function () {
        
        algos[current].digest(_samplesRandom[sample]);
        
        _update();
    
        counter++;
        
        current++;
        
        if (current == 4) {
            current = 0;
            sample++;
            if (sample == 10) {
                sample = 0;
                round++;
            }
        }
    
        // if (round < 10) {
        if (round < 12) {
            window.setTimeout(_step, DELAY);
        } else {
            /* Flush segment buffer. */
            for (var seq = [1, 2, 3, 2, 3, 3], s = 0; s < 6; s++) {
                _renderSegment("rate", seq[s]);
                _renderSegment("time", seq[s]);
            }
        }
        
    };



// written by Dean Edwards, 2005
// with input from Tino Zijdel, Matthias Miller, Diego Perini

// http://dean.edwards.name/weblog/2005/10/add-event/

    var addEvent = function (element, type, handler) {
    	if (element.addEventListener) {
    		element.addEventListener(type, handler, false);
    	} else {
    		// assign each event handler a unique ID
    		if (!handler.$$guid) handler.$$guid = addEvent.guid++;
    		// create a hash table of event types for the element
    		if (!element.events) element.events = {};
    		// create a hash table of event handlers for each element/event pair
    		var handlers = element.events[type];
    		if (!handlers) {
    			handlers = element.events[type] = {};
    			// store the existing event handler (if there is one)
    			if (element["on" + type]) {
    				handlers[0] = element["on" + type];
    			}
    		}
    		// store the event handler in the hash table
    		handlers[handler.$$guid] = handler;
    		// assign a global event handler to do all the work
    		element["on" + type] = handleEvent;
    	}
    };
    // a counter used to create unique IDs
    addEvent.guid = 1;

    /* var removeEvent = function (element, type, handler) {
    	if (element.removeEventListener) {
    		element.removeEventListener(type, handler, false);
    	} else {
    		// delete the event handler from the hash table
    		if (element.events && element.events[type]) {
    			delete element.events[type][handler.$$guid];
    		}
    	}
    }; */

    var handleEvent = function (event) {
    	var returnValue = true;
    	// grab the event object (IE uses a global event object)
    	event = event || fixEvent(((this.ownerDocument || this.document || this).parentWindow || window).event);
    	// get a reference to the hash table of event handlers
    	var handlers = this.events[event.type];
    	// execute each event handler
    	for (var i in handlers) {
    		this.$$handleEvent = handlers[i];
    		if (this.$$handleEvent(event) === false) {
    			returnValue = false;
    		}
    	}
    	return returnValue;
    };

    var fixEvent = function (event) {
    	// add W3C standard event methods
    	event.preventDefault = fixEvent.preventDefault;
    	event.stopPropagation = fixEvent.stopPropagation;
    	return event;
    };
    fixEvent.preventDefault = function() {
    	this.returnValue = false;
    };
    fixEvent.stopPropagation = function() {
    	this.cancelBubble = true;
    };



    /******************************************************************************************************************
     *  SETUP
     */

    /* Setup defered import of this module. */
    global[(new RegExp(/^\w+/)).exec(__name__)][__name__.replace(/^\w+.(\w+)$/, "__$1__")] = {
	    scope:     global,
        namespace: __name__,
        extend:    _extend,
        enumerate: _enumerate,
        decorate:  _decorate,
        sample:    _sample
        };    

}(this);

