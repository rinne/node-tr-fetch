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

async function download(value, signal, body, debug, maxCrlBytes) {
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
            const chunks = [];
            let length = 0;
            if (response.body) {
                for await (const chunk of response.body) {
                    length += chunk.byteLength;
                    if (length > maxBytes) {
                        throw new Error((body === undefined) ? `CRL download exceeds maxCrlBytes (${maxBytes} bytes)` :
                            'OCSP download exceeds the 1 MiB size limit');
                    }
                    chunks.push(chunk);
                }
            }
            debug?.((kind === 'CRL') ? 'CRL fetched' : 'OCSP response fetched', { source: debugUrl(url), bytes: length });
            return Buffer.concat(chunks, length);
        }
        throw new Error(`${kind} download exceeded the five-redirect limit`);
    } finally {
        await agent.destroy();
    }
}

function downloadCrl(value, signal, debug, maxBytes) {
    return download(value, signal, undefined, debug, maxBytes);
}

function downloadOcsp(value, request, signal, debug) {
    return download(value, signal, request, debug);
}

module.exports = { networkUrl, downloadCrl, downloadOcsp };
