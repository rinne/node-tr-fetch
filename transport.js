'use strict';

const { isIP } = require('node:net');
const { Agent, buildConnector, getGlobalDispatcher } = require('undici');
const { version: undiciVersion } = require('undici/package.json');
const { debugUrl } = require('./debug');

// Origins each agent actually connected to, after TLS and revocation checks.
const verifiedOrigins = new WeakMap();

// Do not silently discard a global dispatcher's pinning, proxy, CA or other
// security settings. Node's bundled Agent uses different Symbol identities;
// recognize only its known default configuration and default factory as well.
// Unknown configurations fail closed when Undici's internals change.
const referenceAgent = new Agent();
const factorySymbol = Object.getOwnPropertySymbols(referenceAgent).find(x => x.description === 'factory');
const defaultFactory = Function.prototype.toString.call(referenceAgent[factorySymbol]).replace(/[\s;]/g, '');
void referenceAgent.close();

function isDefaultAgent(agent) {
    if (! agent || (agent.constructor.name !== 'Agent') || Object.hasOwn(agent, 'dispatch')) {
        return false;
    }
    const symbols = Object.getOwnPropertySymbols(agent);
    const options = agent[symbols.find(x => x.description === 'options')];
    const factory = agent[symbols.find(x => x.description === 'factory')];
    return options && (typeof(factory) === 'function') &&
        (Function.prototype.toString.call(factory).replace(/[\s;]/g, '') === defaultFactory) &&
        Object.entries(options).every(([key, value]) =>
            ((key === 'connect') && (value === undefined)) || ((key === 'maxOrigins') && (value === Infinity)));
}

// System fetch drives this package's Agent through the dispatcher handler
// API of its own bundled Undici, which changes between major versions.
function assertCompatibleUndici(bundled = process.versions.undici) {
    const major = version => String(version).split('.')[0];
    if (major(bundled) !== major(undiciVersion)) {
        throw new TypeError(`trFetch uses Undici ${undiciVersion}, which is incompatible with ` +
            `Undici ${bundled} in the fetch of Node.js ${process.version}`);
    }
}

function assertDefaultDispatcher() {
    assertCompatibleUndici();
    if (! isDefaultAgent(getGlobalDispatcher())) {
        throw new TypeError('trFetch requires the default Undici dispatcher; custom or unrecognized global dispatchers cannot be safely replaced');
    }
}

function originOf(options) {
    // Undici passes IPv6 addresses without URL brackets.
    const host = (isIP(options.hostname) === 6) ? `[${options.hostname}]` : options.hostname;
    try {
        return new URL(`${options.protocol}//${host}${options.port ? `:${options.port}` : ''}`).origin;
    } catch (_) {
        return undefined;
    }
}

function createAgent(checkCertificate, signal) {
    const connect = buildConnector({ rejectUnauthorized: true, maxCachedSessions: 0, allowH2: false });
    const origins = new Set();
    const agent = new Agent({
        allowH2: false,
        pipelining: 0,
        connect(options, callback) {
            let socket;
            let finished = false;
            function finish(error) {
                if (finished) {
                    return;
                }
                finished = true;
                signal?.removeEventListener('abort', abort);
                socket?.removeListener('error', finish);
                if (error) {
                    socket?.destroy();
                    callback(error, null);
                } else {
                    origins.add(originOf(options));
                    callback(null, socket);
                }
            }
            function abort() {
                finish(signal.reason);
            }
            if (signal?.aborted) {
                abort();
                return;
            }
            signal?.addEventListener('abort', abort, { once: true });
            // Bind SNI and identity verification to the URL, not a Host header.
            const hostname = options.hostname;
            socket = connect({ ...options, host: hostname, servername: isIP(hostname) ? null : hostname }, function(error, connected) {
                if (finished) {
                    connected?.destroy();
                    return;
                }
                if (error) {
                    finish(error);
                    return;
                }
                if (options.protocol !== 'https:') {
                    finish();
                    return;
                }
                if (! connected.authorized) {
                    finish(new Error(`TLS certificate verification failed: ${connected.authorizationError}`));
                    return;
                }
                connected.disableRenegotiation();
                if (! checkCertificate) {
                    finish();
                    return;
                }
                Promise.resolve().then(function() {
                    return checkCertificate(connected.getPeerCertificate(true), hostname, signal);
                }).then(() => finish(), finish);
            });
            socket.on('error', finish);
            return socket;
        }
    });
    verifiedOrigins.set(agent, origins);
    return agent;
}

// Fail closed if system fetch was replaced or wrapped by code that dropped
// the dispatcher: an HTTP(S) response must come from a connection that this
// agent opened and verified, both for the request and the final URL.
function assertVerifiedResponse(agent, requestUrl, response) {
    if (! [ 'http:', 'https:' ].includes(new URL(requestUrl).protocol)) {
        return;
    }
    const origins = verifiedOrigins.get(agent);
    for (const value of [ requestUrl, response.url || requestUrl ]) {
        let origin;
        try {
            origin = new URL(value).origin;
        } catch (_) {
            origin = undefined;
        }
        if (! origins?.has(origin)) {
            throw new TypeError(`trFetch: the response for ${debugUrl(value)} did not come through the verifying ` +
                'dispatcher; globalThis.fetch may be replaced or wrapped');
        }
    }
}

module.exports = { assertCompatibleUndici, assertDefaultDispatcher, assertVerifiedResponse, createAgent };
