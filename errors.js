'use strict';

const CODES = {
    missingCrlDistributionPoint: 'TR_FETCH_CRL_MISSING_DISTRIBUTION_POINT',
    unreachableCrlDistributionPoint: 'TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT',
    invalidCrl: 'TR_FETCH_CRL_INVALID',
    revokedCertificate: 'TR_FETCH_CERTIFICATE_REVOKED',
    missingOcspUri: 'TR_FETCH_OCSP_MISSING_URI',
    unreachableOcspUri: 'TR_FETCH_OCSP_UNREACHABLE_URI',
    rejectedCertificate: 'TR_FETCH_OCSP_CERTIFICATE_REJECTED',
    ocspNextUpdateMaxClockSkew: 'TR_FETCH_OCSP_NONSTANDARD_VALIDATION',
    noRevocationStatus: 'TR_FETCH_REVOCATION_STATUS_UNAVAILABLE'
};

// The base class of CRL and OCSP errors. Used directly when no check could
// establish a certificate's revocation status (noRevocationStatus).
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

// Deliver error as a warning: warningCb when given, process.emitWarning
// otherwise. The warning's name ends in Warning instead of Error.
function emitWarning(error, warningCb) {
    const warning = new error.constructor(error.policyKey, error.message.slice(9), {}, error.cause);
    Object.assign(warning, error);
    warning.name = error.name.replace(/Error$/, 'Warning');
    if (warningCb) {
        callbackFireAndForget(warningCb, warning);
    } else {
        process.emitWarning(warning);
    }
}

// Apply the configured action for a CRL or OCSP condition.
function applyPolicy(policy, error, debug, warningCb) {
    const action = policy[error.policyKey];
    const kind = (error instanceof TrFetchOcspError) ? 'OCSP' : (error instanceof TrFetchCrlError) ? 'CRL' : 'Revocation';
    debug?.(`${kind} policy applied`, {
        policy: error.policyKey, action, code: error.code, reason: error.message
    });
    if (action === 'reject') {
        throw error;
    }
    if (action === 'warn') {
        emitWarning(error, warningCb);
    }
}

module.exports = { TrFetchRevocationError, TrFetchCrlError, TrFetchOcspError, applyPolicy, emitWarning, callbackFireAndForget };
