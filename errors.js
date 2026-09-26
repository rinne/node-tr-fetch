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

function applyPolicy(policy, error, debug) {
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
        process.emitWarning(warning);
    }
}

module.exports = { TrFetchCrlError, TrFetchOcspError, applyPolicy };
