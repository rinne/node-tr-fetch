'use strict';

const Optist = require('optist');

const TLS_VERSIONS = { '1': 'TLSv1', '1.0': 'TLSv1', '1.1': 'TLSv1.1', '1.2': 'TLSv1.2', '1.3': 'TLSv1.3' };
const TLS_RANK = [ 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3' ];
const SIZE_UNITS = { '': 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3, t: 1024 ** 4, p: 1024 ** 5 };

class UsageError extends Error {}

function sizeCb(value) {
    const match = value.match(/^(\d+)([kmgtp]?)$/i);
    const bytes = match ? Number(match[1]) * SIZE_UNITS[match[2].toLowerCase()] : NaN;
    return Number.isSafeInteger(bytes) ? bytes : undefined;
}

function secondsCb(value) {
    return /^(\d+(\.\d*)?|\.\d+)$/.test(value) ? Number(value) : undefined;
}

function redirectsCb(value) {
    return /^(-1|0|[1-9]\d{0,8})$/.test(value) ? Number(value) : undefined;
}

function tlsMaxCb(value) {
    return (value === 'default') ? value : TLS_VERSIONS[value];
}

function positiveBytesCb(value) {
    return (/^[1-9]\d*$/.test(value) && Number.isSafeInteger(Number(value))) ? Number(value) : undefined;
}

function integerCb(value) {
    return (/^-?(0|[1-9]\d*)$/.test(value) && Number.isSafeInteger(Number(value))) ? Number(value) : undefined;
}

function ttlCb(value) {
    return (/^(-1|0|[1-9]\d*)$/.test(value) && Number.isSafeInteger(Number(value))) ? Number(value) : undefined;
}

function networkUrlCb(value) {
    return (URL.canParse(value) && [ 'http:', 'https:' ].includes(new URL(value).protocol)) ? value : undefined;
}

function jsonObjectCb(value) {
    try {
        const parsed = JSON.parse(value);
        return (parsed && (typeof(parsed) === 'object') && ! Array.isArray(parsed)) ? parsed : undefined;
    } catch (_) {
        return undefined;
    }
}

// Request data options share one ordered list, since curl joins them in the
// order given regardless of which data option supplied each piece.
function dataOptions(arg, tag) {
    return [
        [ 'd', 'data', 'data', '<data> HTTP POST data; @file reads a file with CR and LF removed' ],
        [ undefined, 'data-ascii', 'data', '<data> Same as --data' ],
        [ undefined, 'data-binary', 'binary', '<data> HTTP POST data; @file reads a file as is' ],
        [ undefined, 'data-raw', 'raw', '<data> HTTP POST data without special meaning for @' ],
        [ undefined, 'data-urlencode', 'urlencode', '<data> HTTP POST data, URL-encoded' ],
        [ undefined, 'json', 'json', '<data> HTTP POST JSON; @file reads a file as is' ]
    ].map(([shortName, longName, kind, description]) => arg(shortName, longName, description, tag(kind), true));
}

function optionDefinitions() {
    let seq = 0;
    const tag = kind => value => ({ seq: ++seq, kind, value });
    const flag = (shortName, longName, description, multi = false) => ({ shortName, longName, multi, description });
    const arg = (shortName, longName, description, optArgCb, multi = false) => ({ shortName, longName, hasArg: true, multi, optArgCb,
                                                                                  argName: description.slice(0, description.indexOf(' ')), description: description.slice(description.indexOf(' ') + 1) });
    return [
        arg('A', 'user-agent', '<name> Send User-Agent <name> to server'),
        arg(undefined, 'cacert', '<file> CA certificates (PEM) to use instead of the default trust store'),
        arg(undefined, 'ciphers', '<list> TLS 1.2 and older cipher list (OpenSSL format)'),
        flag(undefined, 'create-dirs', 'Create missing local output directories'),
        arg(undefined, 'crlfile', '<file> Check the server certificate against this CRL (PEM or DER)'),
        ...dataOptions(arg, tag),
        arg('e', 'referer', '<URL> Referrer URL; append ";auto" to update it on redirects'),
        arg(undefined, 'etag-compare', '<file> Send If-None-Match with the ETag read from <file>'),
        flag('f', 'fail', 'Fail fast with no output on HTTP errors'),
        flag(undefined, 'fail-early', 'Stop at the first failed transfer'),
        flag(undefined, 'fail-with-body', 'Fail on HTTP errors but save the body'),
        flag('G', 'get', 'Put the post data in the URL and use GET'),
        arg('H', 'header', '<header/@file> Pass custom header(s) to server', undefined, true),
        flag('h', 'help', 'Show help and exit'),
        flag('I', 'head', 'Show document info only'),
        flag('i', 'include', 'Include response headers in the output'),
        flag('k', 'insecure', 'Skip TLS verification; also bypasses trFetch revocation checks'),
        flag('L', 'location', 'Follow redirects'),
        flag(undefined, 'location-trusted', 'Like --location, and send authentication to other hosts'),
        arg(undefined, 'max-filesize', '<bytes> Maximum file size to download (suffixes k, M, G, T, P)', sizeCb),
        arg(undefined, 'max-redirs', '<num> Maximum number of redirects allowed (default 50, -1 unlimited)', redirectsCb),
        arg('m', 'max-time', '<seconds> Maximum time allowed for each transfer', secondsCb),
        flag(undefined, 'no-progress-meter', 'Do not show the progress meter'),
        arg(undefined, 'oauth2-bearer', '<token> OAuth 2 Bearer Token'),
        arg('o', 'output', '<file> Write to file instead of stdout (one per URL)', undefined, true),
        arg(undefined, 'output-dir', '<dir> Directory to save files in'),
        flag('#', 'progress-bar', 'Display transfer progress as a bar'),
        arg('r', 'range', '<range> Retrieve only the bytes within RANGE'),
        flag('O', 'remote-name', 'Write output to a file named as the remote file (one per URL)', true),
        flag(undefined, 'remote-name-all', 'Use the remote file name for all URLs'),
        flag(undefined, 'remove-on-error', 'Remove output file on errors'),
        arg('X', 'request', '<method> Specify request method to use'),
        flag('s', 'silent', 'Silent mode'),
        flag('S', 'show-error', 'Show error even when -s is used'),
        flag('1', 'tlsv1', 'Use TLSv1.0 or greater'),
        flag(undefined, 'tlsv1.0', 'Use TLSv1.0 or greater'),
        flag(undefined, 'tlsv1.1', 'Use TLSv1.1 or greater'),
        flag(undefined, 'tlsv1.2', 'Use TLSv1.2 or greater'),
        flag(undefined, 'tlsv1.3', 'Use TLSv1.3 or greater'),
        arg(undefined, 'tls-max', '<version> Maximum TLS version: 1.0, 1.1, 1.2, 1.3 or default', tlsMaxCb),
        arg(undefined, 'tls13-ciphers', '<list> TLS 1.3 cipher suites to use'),
        arg(undefined, 'tr-fetch-max-crl-bytes', '<bytes> Largest CRL accepted (default 16777216)', positiveBytesCb),
        arg(undefined, 'tr-fetch-crl-cache-scope', '<crl|certificate> Cache whole CRLs or results per certificate (default certificate)',
            value => [ 'crl', 'certificate' ].includes(value) ? value : undefined),
        arg(undefined, 'tr-fetch-crl-certificate-cache-size', '<count> Cached per-certificate CRL results (default 1024; 0 disables)',
            integerCb),
        arg(undefined, 'tr-fetch-revocation-strategy', '<both|ocsp-first|crl-first> Which revocation checks to run (default ocsp-first)',
            value => [ 'both', 'ocsp-first', 'crl-first' ].includes(value) ? value : undefined),
        arg(undefined, 'tr-fetch-no-revocation-status', '<ignore|warn|reject> When no check establishes a status (default ignore)',
            value => [ 'ignore', 'warn', 'reject' ].includes(value) ? value : undefined),
        arg(undefined, 'tr-fetch-crl-url', '<url> Fetch the server certificate\'s CRL from this URL instead', networkUrlCb),
        arg(undefined, 'tr-fetch-ocsp-cache-size', '<count> Cached OCSP results (default 1024; 0 disables)', integerCb),
        arg(undefined, 'tr-fetch-ocsp-cache-ttl', '<seconds> Longest OCSP result caching (default 86400; 0 disables, -1 no limit)', ttlCb),
        arg(undefined, 'tr-fetch-ocsp-url', '<url> Query this OCSP responder for the server certificate instead', networkUrlCb),
        arg(undefined, 'tr-fetch-options', '<json> Extra trFetch options as a JSON object', jsonObjectCb, true),
        arg('u', 'user', '<user:password> Server user and password (basic authentication)'),
        arg(undefined, 'url', '<url> URL to work with', undefined, true),
        flag('v', 'verbose', 'Make the operation more talkative, including trFetch debug output', true),
        flag('V', 'version', 'Show version number and quit')
    ];
}

function helpText() {
    const lines = optionDefinitions().map(function(o) {
        const names = [ o.shortName && `-${o.shortName}`, `--${o.longName}` ].filter(Boolean).join(', ');
        return [ (o.shortName ? ' ' : '     ') + names + (o.hasArg ? ` ${o.argName}` : ''), o.description ];
    });
    const width = Math.max(...lines.map(x => x[0].length)) + 2;
    return 'Usage: tr-curl [options...] <url>...\n' + lines.map(([left, text]) => left.padEnd(width) + text + '\n').join('');
}

function parseArguments(argv) {
    const opt = (new Optist()).opts(optionDefinitions()).parsePosix(Array.from(argv));
    const value = name => opt.value(name);
    if (value('fail') && value('fail-with-body')) {
        throw new UsageError('--fail and --fail-with-body cannot be used together');
    }
    // Optist cannot preserve the relative order of -o and -O.
    if (value('output').length && value('remote-name')) {
        throw new UsageError('--output and --remote-name cannot be used together');
    }
    const trFetchOptions = Object.assign({}, ...value('tr-fetch-options'));
    for (const key of Object.keys(trFetchOptions)) {
        if (! /^trFetch/.test(key)) {
            throw new UsageError(`--tr-fetch-options accepts only trFetch options, not ${JSON.stringify(key)}`);
        }
    }
    // Dedicated options take precedence over the same settings given in
    // --tr-fetch-options, regardless of their order.
    // Merge settings into a policy object from --tr-fetch-options; a
    // malformed one is left for trFetch to reject.
    function mergePolicy(name, settings) {
        const policy = trFetchOptions[name];
        if ((policy !== undefined) && ! (policy && (typeof(policy) === 'object') && ! Array.isArray(policy))) {
            return;
        }
        const given = Object.entries(settings).filter(([, setting]) => setting !== undefined);
        if (given.length) {
            trFetchOptions[name] = { ...policy, ...Object.fromEntries(given) };
        }
    }
    mergePolicy('trFetchCrlPolicy', {
        maxCrlBytes: value('tr-fetch-max-crl-bytes'),
        crlCertificateCacheSize: value('tr-fetch-crl-certificate-cache-size'),
        crlCacheScope: value('tr-fetch-crl-cache-scope')
    });
    mergePolicy('trFetchCertificateRevocationPolicy', {
        strategy: value('tr-fetch-revocation-strategy'),
        noRevocationStatus: value('tr-fetch-no-revocation-status')
    });
    mergePolicy('trFetchOcspPolicy', {
        ocspCacheSize: value('tr-fetch-ocsp-cache-size'),
        ocspCacheTTL: value('tr-fetch-ocsp-cache-ttl')
    });
    if (value('tr-fetch-crl-url') !== undefined) {
        if (value('crlfile') !== undefined) {
            throw new UsageError('--tr-fetch-crl-url and --crlfile cannot be used together');
        }
        trFetchOptions.trFetchCrlDistributionPointOverride = value('tr-fetch-crl-url');
    }
    if (value('tr-fetch-ocsp-url') !== undefined) {
        trFetchOptions.trFetchOcspUriOverride = value('tr-fetch-ocsp-url');
    }
    const data = [ 'data', 'data-ascii', 'data-binary', 'data-raw', 'data-urlencode', 'json' ]
          .flatMap(value).sort((a, b) => a.seq - b.seq);
    if (value('head') && data.length && ! value('get')) {
        throw new UsageError('You can only select one HTTP request method! You asked for both POST ' +
                             '(using --data or --json) and HEAD (using -I/--head).');
    }
    const tlsMin = [ 'tlsv1.3', 'tlsv1.2', 'tlsv1.1', 'tlsv1.0', 'tlsv1' ].find(value);
    let tlsMax = value('tls-max');
    if (tlsMax === 'default') {
        tlsMax = undefined;
    }
    if (tlsMin && tlsMax && (TLS_RANK.indexOf(TLS_VERSIONS[tlsMin.slice(4)]) > TLS_RANK.indexOf(tlsMax))) {
        throw new UsageError(`--${tlsMin} conflicts with --tls-max ${tlsMax.slice(4)}`);
    }
    return {
        help: value('help'),
        version: value('version'),
        urls: [ ...value('url'), ...opt.rest() ],
        headers: value('header'),
        data,
        json: data.some(x => x.kind === 'json'),
        get: value('get'),
        head: value('head'),
        include: value('include'),
        request: value('request'),
        userAgent: value('user-agent'),
        user: value('user'),
        bearer: value('oauth2-bearer'),
        referer: value('referer'),
        range: value('range'),
        etagCompare: value('etag-compare'),
        location: value('location') || value('location-trusted'),
        locationTrusted: value('location-trusted'),
        maxRedirs: value('max-redirs') ?? 50,
        maxTime: value('max-time'),
        maxFilesize: value('max-filesize') || undefined,
        fail: value('fail'),
        failWithBody: value('fail-with-body'),
        failEarly: value('fail-early'),
        outputs: value('output'),
        outputDir: value('output-dir'),
        createDirs: value('create-dirs'),
        remoteName: value('remote-name'),
        remoteNameAll: value('remote-name-all'),
        removeOnError: value('remove-on-error'),
        silent: value('silent'),
        showError: value('show-error'),
        progressMeter: ! value('no-progress-meter'),
        progressBar: value('progress-bar'),
        verbose: value('verbose') > 0,
        insecure: value('insecure'),
        cacert: value('cacert'),
        crlFile: value('crlfile'),
        ciphers: value('ciphers'),
        tls13Ciphers: value('tls13-ciphers'),
        tlsMin: tlsMin && TLS_VERSIONS[tlsMin.slice(4)],
        tlsMax,
        trFetchOptions
    };
}

module.exports = { parseArguments, helpText, UsageError };
