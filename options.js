'use strict';

const DEFAULT_MAX_CRL_BYTES = 16 * 1024 * 1024;

const DEFAULT_POLICY = {
    disabled: false,
    maxCrlBytes: DEFAULT_MAX_CRL_BYTES,
    crlCacheScope: 'certificate',
    crlCacheSize: 32,
    crlCertificateCacheSize: 1024,
    crlCacheTTL: 86400,
    crlCheckDepth: 0,
    missingCrlDistributionPoint: 'ignore',
    unreachableCrlDistributionPoint: 'reject',
    invalidCrl: 'reject',
    revokedCertificate: 'reject'
};

const DEFAULT_OCSP_POLICY = {
    disabled: false,
    ocspCacheSize: 1024,
    ocspCacheTTL: 86400,
    ocspCheckDepth: 0,
    missingOcspUri: 'ignore',
    unreachableOcspUri: 'reject',
    rejectedCertificate: 'reject'
};

const DEFAULT_REVOCATION_POLICY = {
    strategy: 'ocsp-first',
    noRevocationStatus: 'ignore'
};

const CUSTOM_OPTIONS = [
    'trFetchCertificateRevocationPolicy',
    'trFetchCrlPolicy', 'trFetchCrlDistributionPointOverride', 'trFetchCrlOverride',
    'trFetchOcspPolicy', 'trFetchOcspUriOverride', 'trFetchDebug', 'trFetchWarningCb'
];

const FETCH_OPTIONS = [
    'method', 'headers', 'body', 'referrer', 'referrerPolicy', 'mode',
    'credentials', 'cache', 'redirect', 'integrity', 'keepalive', 'signal',
    'window', 'duplex', 'priority', 'dispatcher'
];

// Web IDL dictionaries also read inherited and non-enumerable properties.
// In particular, never discard an inherited dispatcher or rejection policy.
function copyOptions(value, keys) {
    const copy = { ...value };
    for (const key of keys) {
        if ((value != null) && ! Object.hasOwn(copy, key) && (key in value)) {
            copy[key] = value[key];
        }
    }
    return copy;
}

// Throughout the options, null means the same as undefined: the default.
function parsePolicy(value, defaults, name) {
    if ((value != null) && ((typeof(value) !== 'object') || Array.isArray(value))) {
        throw new TypeError(`${name} must be an object`);
    }
    const policy = { ...defaults };
    for (const [key, setting] of Object.entries(copyOptions(value ?? undefined, Object.keys(defaults)))) {
        if (! Object.hasOwn(defaults, key)) {
            throw new TypeError(`Unknown ${name} property: ${key}`);
        }
        if (setting == null) {
            continue;
        }
        if (key === 'disabled') {
            if (typeof(setting) !== 'boolean') {
                throw new TypeError(`${name}.disabled must be a boolean, null or undefined`);
            }
            policy.disabled = setting;
        } else if (key === 'maxCrlBytes') {
            // Deliberately no value for unlimited; any limit must be explicit.
            if (! Number.isSafeInteger(setting) || (setting <= 0)) {
                throw new TypeError(`${name}.maxCrlBytes must be a positive safe integer (bytes)`);
            }
            policy.maxCrlBytes = setting;
        } else if (key === 'crlCacheScope') {
            if (! [ 'crl', 'certificate' ].includes(setting)) {
                throw new TypeError(`${name}.crlCacheScope must be crl or certificate`);
            }
            policy.crlCacheScope = setting;
        } else if ([ 'crlCacheSize', 'crlCertificateCacheSize', 'ocspCacheSize' ].includes(key)) {
            // Entries; 0 or less disables that cache.
            if (! Number.isSafeInteger(setting)) {
                throw new TypeError(`${name}.${key} must be a safe integer`);
            }
            policy[key] = setting;
        } else if ((key === 'crlCacheTTL') || (key === 'ocspCacheTTL')) {
            // Seconds; -1 means no limit beyond the data's own validity.
            if (! Number.isSafeInteger(setting) || (setting < -1)) {
                throw new TypeError(`${name}.${key} must be -1 or a nonnegative safe integer (seconds)`);
            }
            policy[key] = setting;
        } else if (key === 'strategy') {
            if (! [ 'both', 'ocsp-first', 'crl-first' ].includes(setting)) {
                throw new TypeError(`${name}.strategy must be both, ocsp-first or crl-first`);
            }
            policy.strategy = setting;
        } else if ((key === 'crlCheckDepth') || (key === 'ocspCheckDepth')) {
            policy[key] = parseDepth(setting, `${name}.${key}`);
        } else {
            if (! [ 'ignore', 'warn', 'reject' ].includes(setting)) {
                throw new TypeError(`${name}.${key} must be ignore, warn or reject`);
            }
            policy[key] = setting;
        }
    }
    return policy;
}

function parseDepth(value, name) {
    if (value === 'leaf') {
        return 0;
    }
    if (value === 'full-chain') {
        return Infinity;
    }
    if (! Number.isSafeInteger(value) || (value < 0)) {
        throw new TypeError(`${name} must be a nonnegative safe integer, leaf or full-chain`);
    }
    return value;
}

function splitOptions(options) {
    if ((options !== undefined) && (options !== null) &&
        ((typeof(options) !== 'object') || Array.isArray(options))) {
        throw new TypeError('fetch options must be an object');
    }
    const fetchOptions = copyOptions(options, [ ...FETCH_OPTIONS, ...CUSTOM_OPTIONS ]);
    for (const key in options) {
        if (key.startsWith('trFetch') && ! CUSTOM_OPTIONS.includes(key)) {
            throw new TypeError(`Unknown trFetch option: ${key}`);
        }
    }
    // A trFetch option given as null is the same as one not given.
    for (const key of CUSTOM_OPTIONS) {
        if (fetchOptions[key] === null) {
            fetchOptions[key] = undefined;
        }
    }
    const debugEnabled = fetchOptions.trFetchDebug ?? false;
    if (typeof(debugEnabled) !== 'boolean') {
        throw new TypeError('trFetchDebug must be a boolean, null or undefined');
    }
    // Receives policy warnings instead of process.emitWarning; a fire-and-
    // forget notification whose outcome never affects the fetch.
    const warningCb = fetchOptions.trFetchWarningCb;
    if ((warningCb !== undefined) && (typeof(warningCb) !== 'function')) {
        throw new TypeError('trFetchWarningCb must be a function, null or undefined');
    }
    const policy = parsePolicy(fetchOptions.trFetchCrlPolicy, DEFAULT_POLICY, 'trFetchCrlPolicy');
    const ocspPolicy = parsePolicy(fetchOptions.trFetchOcspPolicy, DEFAULT_OCSP_POLICY, 'trFetchOcspPolicy');
    const revocationPolicy = parsePolicy(fetchOptions.trFetchCertificateRevocationPolicy, DEFAULT_REVOCATION_POLICY,
                                         'trFetchCertificateRevocationPolicy');
    let ocspUri = fetchOptions.trFetchOcspUriOverride;
    if (ocspUri instanceof URL) {
        ocspUri = ocspUri.href;
    }
    if ((ocspUri !== undefined) && (typeof(ocspUri) !== 'string')) {
        throw new TypeError('trFetchOcspUriOverride must be a URL string or URL');
    }
    let distributionPoint = fetchOptions.trFetchCrlDistributionPointOverride;
    let crl = fetchOptions.trFetchCrlOverride;
    if ((distributionPoint !== undefined) && (crl !== undefined)) {
        throw new TypeError('trFetchCrlDistributionPointOverride and trFetchCrlOverride are mutually exclusive');
    }
    if (distributionPoint instanceof URL) {
        distributionPoint = distributionPoint.href;
    }
    if ((distributionPoint !== undefined) && (typeof(distributionPoint) !== 'string')) {
        throw new TypeError('trFetchCrlDistributionPointOverride must be a URL string or URL');
    }
    if (crl !== undefined) {
        if (typeof(crl) === 'string') {
            crl = Buffer.from(crl);
        } else if (crl instanceof Uint8Array) {
            crl = Buffer.from(crl);
        } else if (crl instanceof ArrayBuffer) {
            crl = Buffer.from(new Uint8Array(crl));
        } else {
            throw new TypeError('trFetchCrlOverride must be PEM text or DER/PEM bytes');
        }
    }
    for (const key of CUSTOM_OPTIONS) {
        delete fetchOptions[key];
    }
    if (fetchOptions.dispatcher !== undefined) {
        throw new TypeError('trFetch cannot safely combine CRL checking with a custom dispatcher');
    }
    return { fetchOptions, policy, distributionPoint, crl, ocspPolicy, ocspUri, revocationPolicy, debugEnabled, warningCb };
}

module.exports = { DEFAULT_MAX_CRL_BYTES, splitOptions };
