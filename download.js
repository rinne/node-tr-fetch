'use strict';

const { assertVerifiedResponse, createAgent } = require('./transport');
const { debugUrl } = require('./debug');

function networkUrl(value, kind = 'CRL distribution point') {
    let url;
    try {
        url = new URL(value);
    } catch (_) {
        throw new Error(`${kind} is not an absolute network URL`);
    }
    if (! [ 'http:', 'https:' ].includes(url.protocol)) {
        throw new Error(`Unsupported ${kind} scheme ${url.protocol}; only HTTP and HTTPS are allowed`);
    }
    if (url.username || url.password) {
        throw new Error(`${kind} URLs must not contain credentials`);
    }
    url.hash = '';
    return url;
}

// Read the body into one buffer as it arrives, instead of collecting chunks
// and concatenating them, which needs twice the memory at the end. An
// uncompressed body's Content-Length sizes the buffer up front and lets an
// oversized download fail before it is read; otherwise the buffer grows.
// Only the bytes received are ever exposed.
// The uncompressed body size the server declares, if any. A declared size
// above the limit fails before any of the body is read.
async function declaredLength(response, maxBytes, tooLarge) {
    const declared = response.headers.has('content-encoding') ? NaN : Number(response.headers.get('content-length') ?? NaN);
    const known = Number.isSafeInteger(declared) && (declared >= 0);
    if (known && (declared > maxBytes)) {
        await response.body?.cancel();
        throw new Error(tooLarge);
    }
    return known ? declared : undefined;
}

async function readBody(response, maxBytes, tooLarge) {
    const declared = await declaredLength(response, maxBytes, tooLarge);
    const known = declared !== undefined;
    let buffer = Buffer.allocUnsafeSlow(known ? declared : Math.min(64 * 1024, maxBytes));
    let length = 0;
    for await (const chunk of response.body ?? []) {
        if ((length + chunk.byteLength) > maxBytes) {
            throw new Error(tooLarge);
        }
        if ((length + chunk.byteLength) > buffer.length) {
            const grown = Buffer.allocUnsafeSlow(Math.min(maxBytes, Math.max(length + chunk.byteLength, buffer.length * 2)));
            buffer.copy(grown, 0, 0, length);
            buffer = grown;
        }
        buffer.set(chunk, length);
        length += chunk.byteLength;
    }
    return (length === buffer.length) ? buffer : buffer.subarray(0, length);
}

async function download(value, signal, body, debug, maxCrlBytes, consume) {
    const kind = (body === undefined) ? 'CRL' : 'OCSP';
    const maxBytes = (body === undefined) ? maxCrlBytes : 1024 * 1024;
    let url = networkUrl(value, kind);
    const timeout = AbortSignal.timeout(10000);
    const downloadSignal = signal ? AbortSignal.any([ signal, timeout ]) : timeout;
    const agent = createAgent(undefined, downloadSignal);
    try {
        for (let redirects = 0; redirects <= 5; redirects++) {
            debug?.(`${kind} download started`, { source: debugUrl(url), method: (body === undefined) ? 'GET' : 'POST' });
            const response = await globalThis.fetch(url, {
                dispatcher: agent,
                signal: downloadSignal,
                redirect: 'manual',
                credentials: 'omit',
                referrerPolicy: 'no-referrer',
                method: (body === undefined) ? 'GET' : 'POST',
                body,
                headers: (body === undefined) ? undefined : {
                    'content-type': 'application/ocsp-request',
                    accept: 'application/ocsp-response'
                }
            });
            try {
                assertVerifiedResponse(agent, url.href, response);
            } catch (error) {
                void response.body?.cancel().catch(() => {});
                throw error;
            }
            debug?.(`${kind} HTTP response`, { source: debugUrl(url), status: response.status });
            if ([ 301, 302, 303, 307, 308 ].includes(response.status)) {
                await response.body?.cancel();
                if ((body !== undefined) && ! [ 307, 308 ].includes(response.status)) {
                    throw new Error(`OCSP POST redirect HTTP ${response.status} is unsupported; expected 307 or 308`);
                }
                const location = response.headers.get('location');
                if (! location) {
                    throw new Error(`${kind} redirect has no Location header`);
                }
                const target = networkUrl(new URL(location, url).href, kind);
                debug?.(`${kind} redirect`, { source: debugUrl(url), target: debugUrl(target), status: response.status });
                url = target;
                continue;
            }
            if (response.status !== 200) {
                await response.body?.cancel();
                throw new Error(`${kind} download returned HTTP ${response.status}`);
            }
            const tooLarge = (body === undefined) ? `CRL download exceeds maxCrlBytes (${maxBytes} bytes)` :
                'OCSP download exceeds the 1 MiB size limit';
            if (consume) {
                // The consumer reads the body itself, within the same limits.
                await declaredLength(response, maxBytes, tooLarge);
                const result = await consume(response.body ?? [], downloadSignal);
                debug?.('CRL streamed', { source: debugUrl(url), bytes: result.size });
                return result;
            }
            const result = await readBody(response, maxBytes, tooLarge);
            debug?.((kind === 'CRL') ? 'CRL fetched' : 'OCSP response fetched', { source: debugUrl(url), bytes: result.length });
            return result;
        }
        throw new Error(`${kind} download exceeded the five-redirect limit`);
    } finally {
        await agent.destroy();
    }
}

// With consume, the CRL is not collected: consume(chunks, signal) reads the
// body as it arrives and returns the result, which must report its size.
function downloadCrl(value, signal, debug, maxBytes, consume) {
    return download(value, signal, undefined, debug, maxBytes, consume);
}

function downloadOcsp(value, request, signal, debug) {
    return download(value, signal, request, debug);
}

module.exports = { networkUrl, downloadCrl, downloadOcsp };
