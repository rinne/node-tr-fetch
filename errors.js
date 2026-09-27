'use strict';

const CODES = {
    missingCrlDistributionPoint: 'TR_FETCH_CRL_MISSING_DISTRIBUTION_POINT',
    unreachableCrlDistributionPoint: 'TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT',
    invalidCrl: 'TR_FETCH_CRL_INVALID',
    revokedCertificate: 'TR_FETCH_CERTIFICATE_REVOKED',
    missingOcspUri: 'TR_FETCH_OCSP_MISSING_URI',
    unreachableOcspUri: 'TR_FETCH_OCSP_UNREACHABLE_URI',
    rejectedCertificate: 'TR_FETCH_OCSP_CERTIFICATE_REJECTED'
};

class TrFetchRevocationError extends Error {
    constructor(policyKey, message, details = {}, cause) {
        super(`trFetch: ${message}`, (cause === undefined) ? undefined : { cause });
        this.name = new.target.name;
        this.code = CODES[policyKey];
        this.policyKey = policyKey;
        Object.assign(this, details);
    }
}

class TrFetchCrlError extends TrFetchRevocationError {}
class TrFetchOcspError extends TrFetchRevocationError {}

// Deliver an informational callback without letting it affect the caller:
// it runs asynchronously, and whatever it throws or rejects with is reported
// with console.warn instead of being propagated.
function callbackFireAndForget(...args) {
    (async function() {
        try {
            const cb = args.shift();
            if (typeof(cb) !== 'function') {
                throw new TypeError('Callback not callable');
            }
            await cb(...args);
        } catch (error) {
            console.warn(error);
        }
    })();
}

// Apply the configured action for a CRL or OCSP condition. Warnings go to
// warningCb when given, and to process.emitWarning otherwise.
function applyPolicy(policy, error, debug, warningCb) {
    const action = policy[error.policyKey];
    debug?.((error instanceof TrFetchOcspError) ? 'OCSP policy applied' : 'CRL policy applied', {
        policy: error.policyKey, action, code: error.code, reason: error.message
    });
    if (action === 'reject') {
        throw error;
    }
    if (action === 'warn') {
        const warning = new error.constructor(error.policyKey, error.message.slice(9), {}, error.cause);
        Object.assign(warning, error);
        warning.name = error.name.replace(/Error$/, 'Warning');
        if (warningCb) {
            callbackFireAndForget(warningCb, warning);
        } else {
            process.emitWarning(warning);
        }
    }
}

module.exports = { TrFetchCrlError, TrFetchOcspError, applyPolicy, callbackFireAndForget };
