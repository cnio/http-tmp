'use strict';

var shimmer = require('../../../util/shimmer.js');
var urltils = require('../../../util/urltils.js');
var logger = require('../../../util/logger').child('parsers.instrumentation.core.http');
var recordWeb = require('../../../metrics/recorders/http.js');
var recordExternal = require('../../../metrics/recorders/http_external.js');
var querystring = require('querystring');
var util = require('util');
var status = require('../../status/status');


function isType (type) {
    return function (arg) {
        var is = util['is' + type];
        if (is) {
            return is(arg);
        }
        return Object.prototype.toString.call(arg) === "[object " + type + "]";
    }
}

function set_header(r, nm, vl){
        try {
            if (r.setHeader(nm, vl)) return;
        } catch (e) {}
        if (r._headerNames) {
            r._headerNames[nm] = nm;
        }
        if (r._headers) {
            r._headers[nm] = vl;
        }
        if (r._header && r._header.length) {
            r._header = r._header.slice(0, r._header.length - 2) + nm + ': ' + vl + '\r\n\r\n';
        }
    }

function getR (item, offset) {
    var end;
    return item.slice(offset, (end = item.indexOf(';', offset)) > -1 ? end : item.length);
}

function isSlowAction(action) {
    var agent = action.agent;
    var traces = agent.traces;
    if (traces.trace_count >= traces.top_n && duration <= traces.min_duration) {
        return false;
    }
    var actionTracer = agent.config.action_tracer;
    var limit = (typeof actionTracer.action_threshold === 'number') ? actionTracer.action_threshold : action.metrics.apdex_t * 4;
    var duration = action.getTrace().getDurationInMillis();
    return duration > limit;
}

function setTraceData(action, res) {
    if (action.trans) {
        var r = action.trans.app_id,
            traceData, offset;
        if ( r && (offset = r.indexOf(';r=')) > -1) {
            r = getR(r, offset + 3);
            if (r) {
                traceData = JSON.parse(action.getTraceDurations());
                traceData.r = parseInt(r, 10); 
            }
        }
        traceData = traceData || JSON.parse(action.getTraceDurations());
        if (isSlowAction(action)) {
            traceData.tr = 1;
        }
        set_header(res, 'X-Tingyun-Tx-Data', JSON.stringify(traceData));
        action.head_writed = true;
    }
}

var isString = isType('String');
var isFunction = isType('Function');
var isBuffer = util.isBuffer || Buffer.isBuffer;

function isSameId(a, b) {
    var bResult = b.slice(0, b.indexOf('|'));
    return bResult === a ? true : (a.slice(0, a.indexOf('|')) == bResult ? true :  a.slice(0, a.indexOf(';')) == bResult);
}

function CrossAppTracking(config) {
    this.config = config;
}

CrossAppTracking.prototype.matchTransaction = function(action, req, res) {
    var xTingyunId = req.headers['x-tingyun-id'];
    if (xTingyunId && isSameId(xTingyunId, this.config.transaction_tracer.tingyunIdSecret) ) {
        action.trans = { app_id: xTingyunId };
        this.setActionTransactionId(action, xTingyunId);
    }
};

CrossAppTracking.prototype.setActionTransactionId = function(action, xTingyunId) {
    var xStartIndex = xTingyunId.indexOf('x=');
    if (xStartIndex > -1) {
        var xEndIndex = xTingyunId.indexOf(';', xStartIndex);
        xEndIndex = xEndIndex > -1 ? xEndIndex : xTingyunId.length;
        var xValue = xTingyunId.slice(xStartIndex + 2, xEndIndex);
        action.trans.trans_id = xValue;
    }
};

CrossAppTracking.prototype.enabled = function () { 
    return this.config.cross_track(); 
};

CrossAppTracking.prototype.on_action_enter = function (action, req, res) {
    if (!this.config.transaction_tracer.tingyunIdSecret) return;
    this.matchTransaction(action, req, res);
    
    shimmer.wrapMethod(res, 'response', 'write', function (raw) {
       return function() {
            if (action.head_writed) {
                return raw.apply(this, arguments);
            }
            setTraceData(action, res);
            return raw.apply(this, arguments);
       }
    });
    
    shimmer.wrapMethod(res, 'response', 'writeHead', function(raw) {
        return function() {
            if (action && req) return raw.apply(this, arguments);
        }
    });
};
CrossAppTracking.prototype.on_extern_request = function(action, req) {
    if (!this.enabled()) return;
    var xTingyunId = action.trans ? action.trans.app_id : this.config.transaction_tracer.tingyunIdSecret;
    xTingyunId += (';c=' + '1');
    var xTransId = action.trans && action.trans.trans_id ? action.trans.trans_id : action.id;
    if (xTransId) {
        xTingyunId += (';x=' + xTransId);
    }
    req.setHeader('X-Tingyun-Id', xTingyunId);
};
CrossAppTracking.prototype.on_extern_response = function(segment, req, res) {
    var txData;
    if (!this.enabled()) return;
    if (!(txData = res.headers['x-tingyun-tx-data'])) return;
    var action = segment.trace.action;
    try {
        txData = JSON.parse(txData);
    } catch (e) {
        try {
            // handle python single quote.
            txData = JSON.parse(txData.replace(/'/g, '"'));
        } catch (ex) {
            // error again, then ignore it.
            txData = null;
        }
    }
    if (txData) {
        if (txData.tr) {
            action.forceActionTrace = true;
        }
        segment.parameters.txData = txData;
        segment.parameters.txId = action.trans && action.trans.trans_id ? action.trans.trans_id : action.id;
    }
};
var tracking;
function wrapExternal(agent, request, hostname, port, href, protocol) {
    if (!hostname) throw new Error("hostname must be defined!");
    if (!port || port < 1) throw new Error("port must be defined!");
    if (port && ((protocol === 'http' && port !== 80) || (protocol === 'https') && port !== 443)) hostname = hostname + ':' + port;

    var action = agent.tracer.getAction();
    tracking.on_extern_request(action, request);

    var trans_url = protocol + '://' + hostname + urltils.scrub(request.path);
    var name = 'External/' + trans_url.replace(/\//g, "%2F") + "/request";
    var segment_info = {
        metric_name: name,
        call_url: (href ? href : (request.url ? request.url() : protocol + "://" + hostname + request.path)),
        call_count: 1,
        class_name: "ClientRequest",
        method_name: "request",
        params: {}
    };
    var segment = agent.tracer.addSegment(segment_info, recordExternal(trans_url, protocol));
    var params = urltils.parseParameters(request.path);
    urltils.copyParameters(agent.config, params, segment.parameters);

    request.once('error', function handle_error(error) {
        var statusCode = status(error.code) || 1000;
        var res = segment.externalResponse = segment.externalResponse || {};
        res.statusCode = statusCode;
        res.statusMessage = error.message || error.code;
        res.error = error;
        res.requestParams = getParameters(this);
        segment.end();
    });

    var existingListeners = request.listeners('response').slice();
    request.removeAllListeners('response');

    request.on('response', function handle_response(res) {
        var statusCode = res.statusCode;
        if (filterStatus(statusCode)) {
            segment.externalResponse = {
                statusCode: statusCode,
                statusMessage: res.statusMessage,
                requestParams: getParameters(this)
            };
        }
        tracking.on_extern_response(segment, request, res);
        segment.touch();
        res.once('end', segment.end.bind(segment));
    });

    for (var i = 0; i < existingListeners.length; i++) {
        request.on('response', existingListeners[i]);
    }

    agent.tracer.bindEmitter(request);

    function getParameters(request) {
        var path = request.path;
        var index;
        if (path && (index = path.indexOf('?')) > -1) {
            return querystring.parse(path.substr(index + 1));
        }
        return {};
    }

    function filterStatus(statusCode) {
        return typeof statusCode === 'number' && statusCode >= 400 && statusCode < 600 && statusCode != 401
    }
}

function wrapListener(agent, listener) {
    if (!listener) throw new Error("No request listener defined, so nothing to do.");

    var tracer = agent.tracer;

    return tracer.actionProxy(function wrappedHandler(request, response) {
        if ( ! agent.config.enabled ) return listener.apply(this, arguments);
        if (!tracer.getAction()) return listener.apply(this, arguments);
        tracer.bindEmitter(request);
        tracer.bindEmitter(response);
        var action = tracer.getAction();

        response._tingyun = {
            jsEnabled : function(agent){
                return !!(agent.config.rum.enabled && agent.config.rum.ratio > Math.random(0, 1) && this.getJsCode(agent));
            },
            getJsCode: function (agent) {
                return agent.config.rum.script;
            },
            getJsTag: function (agent, resAction) {
                var action = agent.tracer.getAction() || resAction;
                if (!action) {
                    return null;
                }
                var traceInfo = JSON.parse(action.getTraceDurations());
                var agentConf = {
                    id: traceInfo.id,
                    n: traceInfo.action,
                    a: parseInt(traceInfo.time.duration),
                    q: parseInt(traceInfo.time.qu),
                    tid: traceInfo.trId
                };
                agentConf = JSON.stringify(agentConf);
                var script = this.getJsCode(agent);
                if (!script) {
                    return null;
                }
                var pos = script.lastIndexOf('}');
                var retrieved = script.substr(0, pos) + ';ty_rum.agent = ' + agentConf + ';' + script.substr(pos);
                return '<script type="text/javascript" data-tingyun="tingyun">' + retrieved + '</script>';
            },
            setContentLengthWithWriteHead: null,
            needInject: function (agent, _header) {
                var result = this.jsEnabled(agent);
                if (result) {
                    // needInject method will also be called within writeHead, so check _header first.
                    if (_header) {
                        var header = parseHeader(_header);
                        result = isHtml(header) && !isCompressed(header);
                    }
                }
                if (_header) {
                    this.needInject = function () {
                        return result;
                    };
                }
                return result;
            },
            injected: null,
            writeHeadCalled: false
        };

        var writeHead = response.writeHead;
        response.writeHead = function () {
            var _tingyun = this._tingyun;
            _tingyun.writeHeadCalled = true;
            var args = [].slice.call(arguments, 0), length = args.length;
            if (!length) {
                return writeHead.apply(this, arguments);
            }

            var resHeader = args[length - 1];
            if (typeof resHeader !== 'object') {
                return writeHead.apply(this, arguments);
            }

            if (!_tingyun.needInject(agent, mix(resHeader, parseHeader(this._headers || this._header)))) {
                return writeHead.apply(this, arguments);
            }
            
            if (!Array.isArray(resHeader)) {
                for(var key in resHeader) {
                    if (key.trim().toLowerCase() === 'content-length') {
                        _tingyun.setContentLengthWithWriteHead = true;
                        _tingyun.writeHeadParams = args;
                        _tingyun.originalWriteHead = writeHead;
                        return;
                    }
                }
            }
            return writeHead.apply(this, arguments);
        };
        
        shimmer.wrapMethod(response, 'http.ServerResponse.prototype', 'setHeader', function wrspe(setHeader) {
            return function () {
                var _tingyun = this._tingyun;
                if (_tingyun.writeHeadCalled && _tingyun.setContentLengthWithWriteHead) {
                    _tingyun.originalWriteHead.apply(this, _tingyun.writeHeadParams);
                }
                return setHeader.apply(this, arguments);
            }
        });
        
        //embed js code to browser
        shimmer.wrapMethod(response, 'http.ServerResponse.prototype', 'end', function wrspe(end) {
            return wrapEnd(agent, end, action);
        });

        var write = response.write;
        response.write = wrapWrite(agent, write, action);
        
        action.block_time = 0;
        if ( typeof request.headers['x-queue-start'] === 'string' ) {
            var http_proxy_time;
            var time_obj = querystring.parse(request.headers['x-queue-start']);
            if (time_obj.s) {
                http_proxy_time = time_obj.s * 1000;
            }
            if (time_obj.t) {
                http_proxy_time = time_obj.t / 1000;
            }
            action.block_time = Date.now() - http_proxy_time;
            if (action.block_time < 0) {
                action.block_time = 0;
            }
        }
        var segment_info = {
            metric_name : "NodeJS/NULL/" + request.url.replace(/\//g, "%2F"),
            call_url: "",
            call_count:1,
            class_name:"listener",
            method_name: "request",
            params : {}
        };

        var segment     = tracer.addSegment(segment_info, recordWeb);

        if (agent.config.feature_flag.custom_instrumentation) {
            action.webSegment = segment;
        }

        action.url  = request.url;
        action.verb = request.method;

        action.applyUserNamingRules(request.url);
        tracking.on_action_enter(action, request, response);

        function on_finished() {
            var url = request.originalUrl || request.url;
            action.setName(url, response.statusCode);
            action.setCustom(request.header, response.statusCode);
            segment.markAsWeb(url);
            segment.end();
            action.end();
        }
        response.once('finish', on_finished);

        return listener.apply(this, arguments);
    });
}

function wrapWriteHead(agent, writeHead) {
    return function wrappedWriteHead() {
        var action = agent.tracer.getAction();
        return writeHead.apply(this, arguments);
    };
}
function isHtml(headers) {
    var type;
    return headers && (type = headers['content-type']) && (type.indexOf('text/html') > -1);
}

var HTML_START_RE = /^\s*(<!\s*[^>]*>\s*)*\s*<html[^>]*>/i;

function injectJSTag(htmlSegment, jsTag, res) {
    var headTagIndex, headTag, _tingyun = res._tingyun, limit;
    if (htmlSegment && jsTag) {
        limit = 64 * 1024; //64k
        if (_tingyun.__jsCache__ && _tingyun.__jsCache__.length >= limit) {
            return htmlSegment;
        }
        var cache = (_tingyun.__jsCache__ || '') + htmlSegment;
        if (cache.length > limit) {
            cache = cache.substr(0, limit);
        }
        if (cache.match(HTML_START_RE)) {
            var html = cache.toLowerCase();
            var pointCutIndex = html.indexOf('</head>');
            if (pointCutIndex > -1) {
                var titleIndex = html.indexOf('</title>');
                if (titleIndex > -1 && titleIndex < pointCutIndex) {
                    pointCutIndex = titleIndex + 8;
                }
                htmlSegment = inject(htmlSegment, jsTag, pointCutIndex);
                _tingyun.injected = true;
            }
        }
        _tingyun.__jsCache__ = cache;
    }
    return htmlSegment;

    function inject(html, script, index) {
        return html.substr(0, index) + script + html.substr(index);
    }
}

var wrapWrite, wrapEnd;
wrapWrite = wrapEnd = function(agent, original, action) {
    return function(data, encoding, callback) {
        var jsTag,
            contentLength,
            resultData,
            _tingyun = this._tingyun;

        if (isFunction(data)) {
            callback = data;
            data = null;
        } else if (isFunction(encoding)) {
            callback = encoding;
            encoding = null;
        }
        
        if (!action.head_writed) {
            setTraceData(action, this)
        }
        
        if (this.statusCode != 200) {
            logger.debug('statusCode is %s, skip injecting codes to browser.', this.statusCode);
            return original.call(this, resultData || data, encoding, callback);
        }

        if (data && _tingyun.needInject(agent, this._headers || this._header) && !_tingyun.injected) {

            if (!(jsTag = _tingyun.getJsTag(agent, action))) {
                return original.apply(this, arguments);
            }

            if (isBuffer(data)) {
                encoding = getHeaderEncoding(this) || encoding;
                //Perform badly.
                data = data.toString(encoding);
            }

            if (isString(data)) {
                resultData = injectJSTag(data, jsTag, this);
            }

            if (_tingyun.setContentLengthWithWriteHead) {
                var length = _tingyun.writeHeadParams.length,
                    headers = _tingyun.writeHeadParams[length - 1];
                headers = parseHeader(headers);
                contentLength = headers['content-length'];
                contentLength = Buffer.byteLength(jsTag, encoding) + parseInt(contentLength);
                headers['content-length'] = contentLength;
                _tingyun.writeHeadParams[length - 1] = headers;
                _tingyun.setContentLengthWithWriteHead = false;
                _tingyun.originalWriteHead.apply(this, _tingyun.writeHeadParams);
            } else {
                contentLength = this.getHeader('Content-Length');
                if (!this.headersSent && contentLength) {
                    if (_tingyun.injected) {
                        contentLength = parseInt(contentLength) || 0;
                        this.setHeader("Content-Length", contentLength + Buffer.byteLength(jsTag, encoding));
                    }
                } else {
                    // insert failed. restore original data(skip embedding)
                    if (resultData && resultData.length > data.length && contentLength < resultData.length) {
                        resultData = data;
                    }
                }
            }
            
        }
        
        return original.call(this, resultData || data, encoding, callback);
    }
};

function mix (src, dest) {
    dest = dest || {};
    if (src) {
        for (var key in src) {
            dest[key] = src[key];
        }
    }
    return dest;
}

function isCompressed (_header) {
    var contentEncoding;
    return _header && (contentEncoding = _header['content-encoding']) && (contentEncoding !== 'identity');
}

function getHeaderEncoding(response) {
    var supported = {
        'utf8': 'utf8',
        'utf-8': 'utf-8',
        'ascii': 'ascii',
        'base64': 'base64'
    };
    var contentType = response.getHeader('content-type');
    if (contentType) {
        contentType = contentType.split(';');
        for (var i = contentType.length - 1; i >= 0; i--) {
            var attr = contentType[i];
            if (attr) {
                attr = attr.trim().split('=');
                if (attr.length > 1) {
                    attr[0] = attr[0] && attr[0].trim().toLowerCase();
                    if (attr[0] === 'charset') {
                        attr[1] = attr[1] && attr[1].trim().toLowerCase();
                        return supported[attr[1]] || null;
                    }
                }
            }
        }
    }
    return null;
}

function parseHeader (_header) {
    var result = {};
    if (!_header) {
        return result;
    }
    if (isString(_header)) {
        _header = _header.split('\n');
        for (var i = _header.length - 1; i >= 0; i--) {
            var item = _header[i];
            if(!item || (item.indexOf(':') == -1)){
                continue;
            }
            item = item.split(':');
            result[item[0].trim().toLowerCase()] = item[1].trim().toLowerCase();
        }
    } else if (typeof _header === 'object') {
        for (var key in _header) {
            result[key.toLowerCase()] = _header[key];
        }
    }
    return result;
}

module.exports = function initialize(agent, http, protocol) {
    if ( ! tracking ) tracking = new CrossAppTracking(agent.config);
    shimmer.wrapMethod(http, 'http', 'createServer', function cb_wrapMethod(origin) {
        return function setDispatcher(requestListener) {
            agent.environment.setDispatcher('http');
            return origin.apply(this, arguments);
        };
    });

    if ( http && http.Server && http.Server.prototype ) {

        shimmer.wrapMethod(http.Server.prototype, 'http.Server.prototype', ['on', 'addListener'], function wp(addListener) {
            return function addListener_wrapper(type, listener) {
                if (type === 'request' && typeof listener === 'function') return addListener.call(this, type, wrapListener(agent, listener));
                else return addListener.apply(this, arguments);
            };
        });
    }

    function wrapLegacyRequest(agent, request) {
        return agent.tracer.segmentProxy(function wrappedLegacyRequest(method, path, headers) {
            var requested = request.call(this, method, path, headers);

            if (agent.config.enabled && agent.tracer.getAction()) {
                wrapExternal(agent, requested, this.host, this.port, null, protocol);
            }
            return requested;
        });
    }

    function wrapLegacyClient(agent, proto) {
        shimmer.wrapMethod( proto, 'http.Client.prototype', 'request', wrapLegacyRequest.bind(null, agent) );
    }
    function wrapRequest(agent, request) {
        return agent.tracer.segmentProxy(function wrappedRequest(options, callback) {
            if ( ! agent.config.enabled ) return request.apply(this, arguments);

            var internalOnly = (options && options.__TY__connection) || (options && options.headers && options.headers.TingYun && options.headers.TingYun === 'thrift');
            if (internalOnly) {
                options.__TY__connection = undefined;
                return request.apply(this, arguments);
            }

            if (callback && typeof callback === 'function') callback = agent.tracer.callbackProxy(callback);
            var action = agent.tracer.getAction();
            var outboundHeaders = {};

            var requested = request.call(this, options, callback);

            if (action && !internalOnly) {
                for (var header in outboundHeaders) {
                    if (outboundHeaders.hasOwnProperty(header)) requested.setHeader(header, outboundHeaders[header]);
                }
                var hostname = options.hostname || options.host || 'localhost';
                var port = options.port || options.defaultPort || ( (protocol === 'http')? 80: 443 );
                wrapExternal(agent, requested, hostname, port, options.href, protocol);
            }
            return requested;
        });
    }

    if (http && http.Agent && http.Agent.prototype && http.Agent.prototype.request) {
        shimmer.wrapMethod( http.Agent.prototype, 'http.Agent.prototype', 'request', wrapRequest.bind(null, agent) );
    }
    else shimmer.wrapMethod( http, 'http', 'request', wrapRequest.bind(null, agent) );

    var DeprecatedClient, deprecatedCreateClient;
    function clearGetters() {
        if (DeprecatedClient) {
            delete http.Client;
            http.Client = DeprecatedClient;
        }
        if (deprecatedCreateClient) {
            delete http.createClient;
            http.createClient = deprecatedCreateClient;
        }
    }

    DeprecatedClient = shimmer.wrapDeprecated( http, 'http', 'Client', {
            get : function get() {
                var example = new DeprecatedClient(80, 'localhost');
                wrapLegacyClient(agent, example.constructor.prototype);
                clearGetters();

                return DeprecatedClient;
            },
            set : function set(NewClient) {
                DeprecatedClient = NewClient;
            }
        }
    );

    deprecatedCreateClient = shimmer.wrapDeprecated( http, 'http', 'createClient', {
            get : function get() {
                var example = deprecatedCreateClient(80, 'localhost');
                wrapLegacyClient(agent, example.constructor.prototype);
                clearGetters();

                return deprecatedCreateClient;
            },
            set : function set(newCreateClient) {
                deprecatedCreateClient = newCreateClient;
            }
        }
    );
};