'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const CrlCache = require('../cache');
const { splitOptions } = require('../options');
const { networkUrl } = require('../download');
const { createDebug, debugUrl } = require('../debug');
const { assertCompatibleUndici } = require('../transport');

test('trFetchDebug is strictly boolean, defaults off, and is stripped without mutation', function() {
    assert.equal(splitOptions().debugEnabled, false);
    for (const value of [ undefined, false, true ]) {
        const input = Object.freeze({ trFetchDebug: value, method: 'POST' });
        const result = splitOptions(input);
        assert.equal(result.debugEnabled, value === true);
        assert.deepEqual(result.fetchOptions, { method: 'POST' });
    }
    for (const value of [ null, 0, 1, 'true', {} ]) {
        assert.throws(() => splitOptions({ trFetchDebug: value }), /trFetchDebug must be a boolean/);
    }
    assert.throws(() => splitOptions({ trFetchDebugging: true }), /Unknown trFetch option/);
    for (const input of [ Object.create({ trFetchDebug: true }), Object.defineProperty({}, 'trFetchDebug', { value: true }) ]) {
        const result = splitOptions(input);
        assert.equal(result.debugEnabled, true);
        assert.deepEqual(result.fetchOptions, {});
    }
});

test('debug writes escaped lines to stderr with per-call IDs and sanitized URLs', function(t) {
    const lines = [];
    t.mock.method(process.stderr, 'write', line => { lines.push(line); return true; });
    assert.equal(createDebug(false), undefined);
    const first = createDebug(true);
    first('Example', { reason: 'line one\nline two' });
    first('Another');
    createDebug(true)('Separate');
    assert.equal(lines.length, 3);
    assert.equal(lines[0].split('\n').length, 2);
    assert.equal(JSON.parse(lines[0].slice(lines[0].indexOf('{'))).reason, 'line one\nline two');
    const ids = lines.map(line => line.match(/debug #(\d+)/)[1]);
    assert.equal(ids[0], ids[1]);
    assert.notEqual(ids[0], ids[2]);
    assert.equal(debugUrl('https://user:password@example.com/crl?token=secret#fragment'), 'https://example.com/crl');
    assert.equal(debugUrl('file:///private/secret'), 'file:[unsupported]');
    assert.equal(debugUrl('not a URL'), '[invalid URL]');
    t.mock.method(process.stderr, 'write', () => { throw new Error('broken stderr'); });
    assert.doesNotThrow(() => first('Example'));
});

test('cache diagnostics explain misses, hits, expiration, capacity purges and disabled caching', function() {
    const cache = new CrlCache();
    const events = [];
    const debug = (event, details) => events.push({ event, ...details });
    const a = 'issuer:https://ca.example/a?secret=token';
    const b = 'issuer:https://ca.example/b';
    assert.equal(cache.get(a, 1, 2, 1000, debug), undefined);
    cache.set(a, 'A', 10000, 1000, 1, 2, 1000, debug);
    assert.equal(cache.get(a, 1, 2, 2000, debug), 'A');
    assert.equal(cache.get(a, 1, 2, 3000, debug), undefined);
    cache.set(a, 'A', 4000, 3000, 1, -1, 3000, debug);
    assert.equal(cache.get(a, 1, -1, 4000, debug), undefined);
    cache.set(a, 'A', 20000, 4000, 1, -1, 4000, debug);
    assert.equal(cache.get(a, 1, 1, 5000, debug), undefined);
    cache.set(a, 'A', 20000, 5000, 1, -1, 5000, debug);
    cache.set(b, 'B', 20000, 5000, 1, -1, 5000, debug);
    assert.equal(cache.get(b, 1, 0, 5000, debug), undefined);
    assert.equal(cache.get(b, 0, -1, 5000, debug), undefined);
    cache.set(b, 'B', 20000, 5000, 0, -1, 5000, debug);
    assert.deepEqual(events.filter(x => x.event === 'CRL cache expired').map(x => x.reason), [ 'TTL', 'CRL nextUpdate', 'caller TTL' ]);
    assert.deepEqual(events.filter(x => x.event === 'CRL cache purged').map(x => x.reason), [ 'LRU capacity', 'cache disabled' ]);
    for (const event of [ 'CRL cache miss', 'CRL cache stored', 'CRL cache hit', 'CRL cache bypassed', 'CRL cache store skipped' ]) {
        assert.ok(events.some(x => x.event === event), event);
    }
    assert.ok(events.every(x => ! x.source.includes('?')));
});

test('defaults, partial policy and stripping without mutating caller options', function() {
    const input = Object.freeze({ method: 'POST', trFetchCrlPolicy: Object.freeze({ invalidCrl: 'warn' }), trFetchCrlCacheTTL: -1 });
    const options = splitOptions(input);
    assert.deepEqual(options.fetchOptions, { method: 'POST' });
    assert.equal(options.cacheSize, 32);
    assert.equal(options.cacheTTL, -1);
    assert.deepEqual(options.policy, {
        disabled: false, maxCrlBytes: 16777216,
        missingCrlDistributionPoint: 'ignore', unreachableCrlDistributionPoint: 'reject', invalidCrl: 'warn', revokedCertificate: 'reject'
    });
    assert.equal(splitOptions().cacheTTL, 1800);
    assert.equal(splitOptions().checkDepth, 0);
});

test('maxCrlBytes accepts only an explicit positive number of bytes, and only for CRLs', function() {
    for (const value of [ 1, 16777216, 64 * 1024 * 1024, Number.MAX_SAFE_INTEGER ]) {
        assert.equal(splitOptions({ trFetchCrlPolicy: { maxCrlBytes: value } }).policy.maxCrlBytes, value);
    }
    for (const value of [ 0, -1, 1.5, NaN, Infinity, 2 ** 53, '16777216', null, undefined, true, 16777216n ]) {
        assert.throws(() => splitOptions({ trFetchCrlPolicy: { maxCrlBytes: value } }), /maxCrlBytes must be a positive safe integer/);
    }
    assert.throws(() => splitOptions({ trFetchOcspPolicy: { maxCrlBytes: 1 } }), /Unknown trFetchOcspPolicy property/);
});

test('reject unknown policy keys, invalid values, conflicting overrides and custom dispatchers', function() {
    for (const options of [
        { trFetchBogus: true }, { trFetchCrlPolicy: null }, { trFetchCrlPolicy: { invalidCrl: 'allow' } },
        { trFetchCrlPolicy: { typo: 'ignore' } }, { trFetchCrlCacheSize: 1.2 }, { trFetchCrlCacheTTL: -2 },
        { trFetchCrlCacheTTL: Infinity }, { trFetchCrlOverride: {} }, { trFetchCrlDistributionPointOverride: null },
        { trFetchCrlOverride: '', trFetchCrlDistributionPointOverride: '' }, { dispatcher: {} },
        { trFetchCrlCheckDepth: -1 }, { trFetchCrlCheckDepth: Infinity }, { trFetchCrlCheckDepth: 'all' }
    ]) {
        assert.throws(() => splitOptions(options), TypeError);
    }
    assert.equal(splitOptions({ trFetchCrlCacheSize: -32 }).cacheSize, -32);
});

test('numeric and named CRL check depth', function() {
    for (const [input, output] of [ [ 0, 0 ], [ 1, 1 ], [ 10, 10 ], [ 'leaf', 0 ], [ 'full-chain', Infinity ] ]) {
        const result = splitOptions({ trFetchCrlCheckDepth: input });
        assert.equal(result.checkDepth, output);
        assert.deepEqual(result.fetchOptions, {});
    }
});

test('inherited options and non-enumerable security settings cannot be silently dropped', function() {
    assert.throws(() => splitOptions(Object.create({ dispatcher: {} })), /custom dispatcher/);
    assert.throws(() => splitOptions(Object.defineProperty({}, 'dispatcher', { value: {} })), /custom dispatcher/);
    const result = splitOptions(Object.create({
        method: 'POST', trFetchCrlCheckDepth: 1,
        trFetchCrlPolicy: Object.create({ missingCrlDistributionPoint: 'reject' })
    }));
    assert.equal(result.fetchOptions.method, 'POST');
    assert.equal(result.checkDepth, 1);
    assert.equal(result.policy.missingCrlDistributionPoint, 'reject');
});

test('override bytes are copied to prevent caller mutation during validation', function() {
    const bytes = Buffer.from('original');
    const options = splitOptions({ trFetchCrlOverride: bytes });
    bytes.fill(0);
    assert.equal(options.crl.toString(), 'original');
});

test('cache expires by TTL and nextUpdate, with no sliding TTL', function() {
    const cache = new CrlCache();
    cache.set('a', 'A', 10000, 1000, 32, 2, 1000);
    assert.equal(cache.get('a', 32, -1, 2999), 'A');
    assert.equal(cache.get('a', 32, -1, 3000), undefined);
    cache.set('a', 'A', 2000, 1000, 32, -1, 1000);
    assert.equal(cache.get('a', 32, -1, 1999), 'A');
    assert.equal(cache.get('a', 32, -1, 2000), undefined);
});

test('cache honors a later caller shorter TTL, LRU eviction and disabled cache', function() {
    const cache = new CrlCache();
    cache.set('a', 'A', 100000, 1000, 2, -1, 1000);
    cache.set('b', 'B', 100000, 1000, 2, -1, 1000);
    assert.equal(cache.get('a', 2, -1, 1500), 'A');
    cache.set('c', 'C', 100000, 1500, 2, -1, 1500);
    assert.equal(cache.get('b', 2, -1, 1500), undefined);
    assert.equal(cache.get('a', 2, 1, 2000), undefined);
    assert.equal(cache.get('c', 2, 0, 2000), undefined);
    assert.equal(cache.get('c', -1, -1, 2000), undefined);
    for (const [size, ttl] of [ [ 0, -1 ], [ -2, -1 ], [ 32, 0 ] ]) {
        cache.set('x', 'X', 100000, 1000, size, ttl, 1000);
        assert.equal(cache.get('x', 32, -1, 1000), undefined);
    }
});

test('CRL URLs accept only HTTP(S), never files, LDAP or URL credentials', function() {
    for (const url of [ 'file:///tmp/a.crl', '/tmp/a.crl', 'ldap://localhost/cn=CA', 'ldaps://ca.example/crl',
                        'data:,crl', 'ftp://example.com/a.crl', 'http://user:secret@example.com/a.crl' ]) {
        assert.throws(() => networkUrl(url));
    }
    assert.equal(networkUrl('http://example.com/a.crl#part').href, 'http://example.com/a.crl');
    assert.equal(networkUrl('https://example.com/a.crl').protocol, 'https:');
});

test('OCSP defaults, depth, override and disabled policy options are validated and stripped', function() {
    assert.deepEqual(splitOptions().ocspPolicy, {
        disabled: false, missingOcspUri: 'ignore', unreachableOcspUri: 'reject', rejectedCertificate: 'reject'
    });
    for (const [depth, expected] of [ [ undefined, 0 ], [ 0, 0 ], [ 'leaf', 0 ], [ 2, 2 ], [ 'full-chain', Infinity ] ]) {
        const result = splitOptions({ trFetchOcspCheckDepth: depth, trFetchOcspUriOverride: new URL('https://ca.example/ocsp') });
        assert.equal(result.ocspCheckDepth, expected);
        assert.equal(result.ocspUri, 'https://ca.example/ocsp');
        assert.deepEqual(result.fetchOptions, {});
    }
    for (const key of [ 'trFetchCrlPolicy', 'trFetchOcspPolicy' ]) {
        for (const disabled of [ undefined, null, false, true ]) {
            const result = splitOptions({ [key]: Object.create({ disabled }) });
            assert.equal((key === 'trFetchCrlPolicy' ? result.policy : result.ocspPolicy).disabled, disabled === true);
        }
        for (const disabled of [ 0, 1, 'true', [], {} ]) {
            assert.throws(() => splitOptions({ [key]: { disabled } }), TypeError);
        }
    }
    for (const options of [ { trFetchOcspPolicy: null }, { trFetchOcspPolicy: { missingOcspUri: 'allow' } },
                            { trFetchOcspPolicy: { typo: 'ignore' } }, { trFetchOcspCheckDepth: -1 }, { trFetchOcspCheckDepth: 1.5 },
                            { trFetchOcspUriOverride: null }, { trFetchOcspUriOverride: {} } ]) {
        assert.throws(() => splitOptions(options), TypeError);
    }
});

test('system fetch must use the same Undici major version as trFetch', function() {
    const [major, minor] = require('undici/package.json').version.split('.').map(Number);
    assertCompatibleUndici();
    assertCompatibleUndici(`${major}.${minor + 1}.0`);
    for (const bundled of [ `${major - 1}.29.1`, `${major + 1}.0.0` ]) {
        assert.throws(() => assertCompatibleUndici(bundled), /incompatible with Undici/);
    }
});
