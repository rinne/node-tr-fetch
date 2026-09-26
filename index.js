'use strict';

const { splitOptions } = require('./options');
const { assertDefaultDispatcher, assertVerifiedResponse, createAgent } = require('./transport');
const { checkChain } = require('./check');
const { TrFetchCrlError, TrFetchOcspError } = require('./errors');
const { createDebug, debugUrl } = require('./debug');

async function trFetch(input, options) {
    const config = splitOptions(options);
    const debug = createDebug(config.debugEnabled);
    config.debug = debug;
    assertDefaultDispatcher();
    const request = new Request(input, config.fetchOptions);
    const signal = request.signal;
    signal.throwIfAborted();
    debug?.('Verification configured', {
        url: debugUrl(request.url),
        crl: config.policy.disabled ? 'disabled' : 'enabled',
        crlDepth: (config.checkDepth === Infinity) ? 'full-chain' : config.checkDepth,
        ocsp: config.ocspPolicy.disabled ? 'disabled' : 'enabled',
        ocspDepth: (config.ocspCheckDepth === Infinity) ? 'full-chain' : config.ocspCheckDepth
    });
    const check = (config.policy.disabled && config.ocspPolicy.disabled) ? undefined :
          (peer, hostname) => checkChain(peer, hostname, config, signal);
    const agent = createAgent(check, signal);
    try {
        const response = await globalThis.fetch(request, { dispatcher: agent });
        try {
            assertVerifiedResponse(agent, request.url, response);
        } catch (error) {
            void response.body?.cancel().catch(() => {});
            throw error;
        }
        debug?.('Fetch response received', { url: debugUrl(response.url || request.url), status: response.status });
        // close() waits for body consumption; do not await it before returning
        // the response, or streaming responses would deadlock.
        void agent.close().catch(() => {});
        return response;
    } catch (error) {
        debug?.('Fetch failed', { aborted: signal.aborted, code: error.cause?.code ?? error.code ?? 'FETCH_FAILED' });
        await agent.destroy();
        if (signal.aborted) {
            throw signal.reason;
        }
        for (let cause = error; cause; cause = cause.cause) {
            if ((cause instanceof TrFetchCrlError) || (cause instanceof TrFetchOcspError)) {
                throw cause;
            }
        }
        throw error;
    }
}

module.exports = trFetch;
module.exports.TrFetchCrlError = TrFetchCrlError;
module.exports.TrFetchOcspError = TrFetchOcspError;
