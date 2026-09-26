'use strict';

let nextId = 0;

function debugUrl(value) {
    try {
        const url = new URL(value);
        if (! [ 'http:', 'https:' ].includes(url.protocol)) {
            return url.protocol + '[unsupported]';
        }
        return url.origin + url.pathname;
    } catch (_) {
        return '[invalid URL]';
    }
}

function createDebug(enabled) {
    if (! enabled) {
        return undefined;
    }
    const id = ++nextId;
    return function(event, details = {}) {
        // One escaped line per event, with a per-fetch ID for concurrent calls.
        // Never include request headers, bodies or raw certificate/CRL data.
        try {
            process.stderr.write(`[trFetch debug #${id}] ${event} ${JSON.stringify(details)}\n`);
        } catch (_) {
            // Diagnostics must not change the verification outcome.
        }
    };
}

module.exports = { createDebug, debugUrl };
