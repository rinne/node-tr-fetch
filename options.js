'use strict';

const DEFAULT_MAX_CRL_BYTES = 16 * 1024 * 1024;

const DEFAULT_POLICY = {
    disabled: false,
    maxCrlBytes: DEFAULT_MAX_CRL_BYTES,
    crlCacheScope: 'crl',
    crlCacheSize: 32,
    crlCertificateCacheSize: 1024,
    crlCacheTTL: 1800,
    crlCheckDepth: 0,
    missingCrlDistributionPoint: 'ignore',
    unreachableCrlDistributionPoint: 'reject',
    invalidCrl: 'reject',
    revokedCertificate: 'reject'
};

const DEFAULT_OCSP_POLICY = {
    disabled: false,
    ocspCheckDepth: 0,
    missingOcspUri: 'ignore',
    unreachableOcspUri: 'reject',
    rejectedCertificate: 'reject'
};

const CUSTOM_OPTIONS = [
    'trFetchCrlPolicy', 'trFetchCrlDistributionPointOverride', 'trFetchCrlOverride',
    'trFetchOcspPolicy', 'trFetchOcspUriOverride', 'trFetchDebug'
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

function parsePolicy(value, defaults, name) {
    if ((value !== undefined) &&
        ((value === null) || (typeof(value) !== 'object') || Array.isArray(value))) {
        throw new TypeError(`${name} must be an object`);
    }
    const policy = { ...defaults };
    for (const [key, setting] of Object.entries(copyOptions(value, Object.keys(defaults)))) {
        if (! Object.hasOwn(defaults, key)) {
            throw new TypeError(`Unknown ${name} property: ${key}`);
        }
        if (key === 'disabled') {
            if ((setting != null) && (typeof(setting) !== 'boolean')) {
                throw new TypeError(`${name}.disabled must be a boolean, null or undefined`);
            }
            policy.disabled = setting ?? false;
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
        } else if ((key === 'crlCacheSize') || (key === 'crlCertificateCacheSize')) {
            // Entries; 0 or less disables that cache. Null means the default.
            if ((setting != null) && ! Number.isSafeInteger(setting)) {
                throw new TypeError(`${name}.${key} must be a safe integer`);
            }
            policy[key] = setting ?? defaults[key];
        } else if (key === 'crlCacheTTL') {
            if ((setting != null) && (! Number.isSafeInteger(setting) || (setting < -1))) {
                throw new TypeError(`${name}.crlCacheTTL must be -1 or a nonnegative safe integer (seconds)`);
            }
            policy.crlCacheTTL = setting ?? defaults.crlCacheTTL;
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
    if ((value == null) || (value === 'leaf')) {
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
    const debugEnabled = (fetchOptions.trFetchDebug === undefined) ? false : fetchOptions.trFetchDebug;
    if (typeof(debugEnabled) !== 'boolean') {
        throw new TypeError('trFetchDebug must be a boolean');
    }
    const policy = parsePolicy(fetchOptions.trFetchCrlPolicy, DEFAULT_POLICY, 'trFetchCrlPolicy');
    const ocspPolicy = parsePolicy(fetchOptions.trFetchOcspPolicy, DEFAULT_OCSP_POLICY, 'trFetchOcspPolicy');
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
    return { fetchOptions, policy, distributionPoint, crl, ocspPolicy, ocspUri, debugEnabled };
}

module.exports = { DEFAULT_MAX_CRL_BYTES, splitOptions };
