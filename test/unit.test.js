'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const CrlCache = require('../cache');
const { splitOptions } = require('../options');
const { networkUrl } = require('../download');
const { createDebug, debugUrl } = require('../debug');
const { assertCompatibleUndici } = require('../transport');

test('trFetchDebug is boolean, off for undefined and null, and is stripped without mutation', function() {
    assert.equal(splitOptions().debugEnabled, false);
    for (const value of [ undefined, null, false, true ]) {
        const input = Object.freeze({ trFetchDebug: value, method: 'POST' });
        const result = splitOptions(input);
        assert.equal(result.debugEnabled, value === true);
        assert.deepEqual(result.fetchOptions, { method: 'POST' });
    }
    for (const value of [ 0, 1, 'true', 'false', {}, [] ]) {
        assert.throws(() => splitOptions({ trFetchDebug: value }), /trFetchDebug must be a boolean, null or undefined/);
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
    const input = Object.freeze({ method: 'POST', trFetchCrlPolicy: Object.freeze({ invalidCrl: 'warn', crlCacheTTL: -1 }) });
    const options = splitOptions(input);
    assert.deepEqual(options.fetchOptions, { method: 'POST' });
    assert.deepEqual(options.policy, {
        disabled: false, maxCrlBytes: 16777216, crlCacheScope: 'certificate', crlCacheSize: 32, crlCertificateCacheSize: 1024,
        crlCacheTTL: -1, crlCheckDepth: 0,
        missingCrlDistributionPoint: 'ignore', unreachableCrlDistributionPoint: 'reject', invalidCrl: 'warn', revokedCertificate: 'reject'
    });
    assert.equal(splitOptions().policy.crlCacheTTL, 86400);
    assert.equal(splitOptions().policy.crlCheckDepth, 0);
    assert.deepEqual(Object.keys(splitOptions()).sort(), [ 'crl', 'debugEnabled', 'distributionPoint', 'fetchOptions', 'ocspPolicy',
        'ocspUri', 'policy', 'revocationPolicy', 'warningCb' ]);
});

test('cache sizes, TTL and check depths are policy settings; the former top-level options are unknown', function() {
    for (const key of [ 'crlCacheSize', 'crlCertificateCacheSize' ]) {
        for (const value of [ -32, 0, 1, 5000, Number.MAX_SAFE_INTEGER ]) {
            assert.equal(splitOptions({ trFetchCrlPolicy: { [key]: value } }).policy[key], value, key);
        }
        for (const value of [ undefined, null ]) {
            assert.equal(splitOptions({ trFetchCrlPolicy: { [key]: value } }).policy[key], (key === 'crlCacheSize') ? 32 : 1024);
        }
        for (const value of [ 1.2, Infinity, NaN, '32', true, 2 ** 53 ]) {
            assert.throws(() => splitOptions({ trFetchCrlPolicy: { [key]: value } }), new RegExp(`${key} must be a safe integer`));
        }
    }
    for (const value of [ -1, 0, 1, 86400 ]) {
        assert.equal(splitOptions({ trFetchCrlPolicy: { crlCacheTTL: value } }).policy.crlCacheTTL, value);
    }
    assert.equal(splitOptions({ trFetchCrlPolicy: { crlCacheTTL: null } }).policy.crlCacheTTL, 86400);
    for (const value of [ -2, 1.5, Infinity, '1800', true ]) {
        assert.throws(() => splitOptions({ trFetchCrlPolicy: { crlCacheTTL: value } }), /crlCacheTTL must be -1 or a nonnegative safe integer/);
    }
    for (const [key, policy] of [ [ 'crlCheckDepth', 'trFetchCrlPolicy' ], [ 'ocspCheckDepth', 'trFetchOcspPolicy' ] ]) {
        for (const [input, output] of [ [ undefined, 0 ], [ null, 0 ], [ 0, 0 ], [ 1, 1 ], [ 10, 10 ], [ 'leaf', 0 ], [ 'full-chain', Infinity ] ]) {
            const result = splitOptions({ [policy]: { [key]: input } });
            assert.equal(result[(policy === 'trFetchCrlPolicy') ? 'policy' : 'ocspPolicy'][key], output, `${key} ${input}`);
            assert.deepEqual(result.fetchOptions, {});
        }
        for (const input of [ -1, 1.5, Infinity, 'all', '1' ]) {
            assert.throws(() => splitOptions({ [policy]: { [key]: input } }), new RegExp(`${policy}\\.${key} must be`));
        }
    }
    for (const key of [ 'crlCacheSize', 'crlCertificateCacheSize', 'crlCacheTTL', 'crlCheckDepth' ]) {
        assert.throws(() => splitOptions({ trFetchOcspPolicy: { [key]: 0 } }), /Unknown trFetchOcspPolicy property/);
    }
    assert.throws(() => splitOptions({ trFetchCrlPolicy: { ocspCheckDepth: 0 } }), /Unknown trFetchCrlPolicy property/);
    for (const key of [ 'trFetchCrlCacheSize', 'trFetchCrlCacheTTL', 'trFetchCrlCheckDepth', 'trFetchOcspCheckDepth' ]) {
        assert.throws(() => splitOptions({ [key]: 0 }), new RegExp(`Unknown trFetch option: ${key}`));
    }
});

test('maxCrlBytes accepts only an explicit positive number of bytes, and only for CRLs', function() {
    for (const value of [ 1, 16777216, 64 * 1024 * 1024, Number.MAX_SAFE_INTEGER ]) {
        assert.equal(splitOptions({ trFetchCrlPolicy: { maxCrlBytes: value } }).policy.maxCrlBytes, value);
    }
    for (const value of [ 0, -1, 1.5, NaN, Infinity, 2 ** 53, '16777216', true, 16777216n ]) {
        assert.throws(() => splitOptions({ trFetchCrlPolicy: { maxCrlBytes: value } }), /maxCrlBytes must be a positive safe integer/);
    }
    assert.throws(() => splitOptions({ trFetchOcspPolicy: { maxCrlBytes: 1 } }), /Unknown trFetchOcspPolicy property/);
});

test('reject unknown policy keys, invalid values, conflicting overrides and custom dispatchers', function() {
    for (const options of [
        { trFetchBogus: true }, { trFetchCrlPolicy: 'crl' }, { trFetchCrlPolicy: { invalidCrl: 'allow' } },
        { trFetchCrlPolicy: { typo: 'ignore' } }, { trFetchCrlPolicy: { crlCacheSize: 1.2 } }, { trFetchCrlPolicy: { crlCacheTTL: -2 } },
        { trFetchCrlPolicy: { crlCacheTTL: Infinity } }, { trFetchCrlOverride: {} }, { trFetchCrlDistributionPointOverride: 1 },
        { trFetchCrlOverride: '', trFetchCrlDistributionPointOverride: '' }, { dispatcher: {} },
        { trFetchCrlPolicy: { crlCheckDepth: -1 } }, { trFetchCrlPolicy: { crlCheckDepth: Infinity } },
        { trFetchCrlPolicy: { crlCheckDepth: 'all' } }
    ]) {
        assert.throws(() => splitOptions(options), TypeError);
    }
});

test('inherited options and non-enumerable security settings cannot be silently dropped', function() {
    assert.throws(() => splitOptions(Object.create({ dispatcher: {} })), /custom dispatcher/);
    assert.throws(() => splitOptions(Object.defineProperty({}, 'dispatcher', { value: {} })), /custom dispatcher/);
    const result = splitOptions(Object.create({
        method: 'POST',
        trFetchCrlPolicy: Object.create({ missingCrlDistributionPoint: 'reject', crlCheckDepth: 1 })
    }));
    assert.equal(result.fetchOptions.method, 'POST');
    assert.equal(result.policy.crlCheckDepth, 1);
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
        disabled: false, ocspCacheSize: 1024, ocspCacheTTL: 86400, ocspCheckDepth: 0,
        missingOcspUri: 'ignore', unreachableOcspUri: 'reject', rejectedCertificate: 'reject'
    });
    for (const [depth, expected] of [ [ undefined, 0 ], [ 0, 0 ], [ 'leaf', 0 ], [ 2, 2 ], [ 'full-chain', Infinity ] ]) {
        const result = splitOptions({ trFetchOcspPolicy: { ocspCheckDepth: depth }, trFetchOcspUriOverride: new URL('https://ca.example/ocsp') });
        assert.equal(result.ocspPolicy.ocspCheckDepth, expected);
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
    for (const options of [ { trFetchOcspPolicy: [] }, { trFetchOcspPolicy: { missingOcspUri: 'allow' } },
                            { trFetchOcspPolicy: { typo: 'ignore' } }, { trFetchOcspPolicy: { ocspCheckDepth: -1 } },
                            { trFetchOcspPolicy: { ocspCheckDepth: 1.5 } },
                            { trFetchOcspUriOverride: 1 }, { trFetchOcspUriOverride: {} } ]) {
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

test('every module the package loads is listed in package.json files', function() {
    const fs = require('node:fs');
    const path = require('node:path');
    const root = path.join(__dirname, '..');
    const { files, main, bin } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    // npm always includes package.json itself.
    const listed = file => (file === 'package.json') || files.some(entry => entry.endsWith('/') ? file.startsWith(entry) : (file === entry));
    const pending = [ main, ...Object.values(bin) ];
    const seen = new Set();
    while (pending.length) {
        const file = path.normalize(pending.pop());
        if (seen.has(file)) {
            continue;
        }
        seen.add(file);
        assert.ok(listed(file), `${file} is not in package.json files`);
        if (! file.endsWith('.js')) {
            continue;
        }
        const source = fs.readFileSync(path.join(root, file), 'utf8');
        for (const [, target] of source.matchAll(/require\('(\.{1,2}(?:\/[^']*)?)'\)/g)) {
            const resolved = path.relative(root, require.resolve(path.join(root, path.dirname(file), target)));
            pending.push(resolved);
        }
    }
    assert.ok(seen.has('serials.js'));
});

test('crlCacheScope accepts crl or certificate, only in the CRL policy', function() {
    assert.equal(splitOptions().policy.crlCacheScope, 'certificate');
    for (const value of [ 'crl', 'certificate' ]) {
        assert.equal(splitOptions({ trFetchCrlPolicy: { crlCacheScope: value } }).policy.crlCacheScope, value);
    }
    for (const value of [ 'CRL', 'Certificate', 'cert', '', 1, true, [ 'crl' ] ]) {
        assert.throws(() => splitOptions({ trFetchCrlPolicy: { crlCacheScope: value } }), /crlCacheScope must be crl or certificate/);
    }
    assert.throws(() => splitOptions({ trFetchOcspPolicy: { crlCacheScope: 'crl' } }), /Unknown trFetchOcspPolicy property/);
});

test('per-certificate CRL results: fresh hits, stale candidates, and results that never go backwards', function() {
    const { CrlResultCache, STALE_CANDIDATE_LIFETIME } = require('../cache');
    const cache = new CrlResultCache();
    const events = [];
    const debug = (event, details) => events.push({ event, ...details });
    const fields = (id, group, thisUpdate, listed = false) => ({ issuerId: 'i', certificateId: id, url: `http://ca.example/${group}.crl`,
        group, serial: Buffer.from(id), isCA: false, urls: [ `http://ca.example/${group}.crl` ], listed,
        thisUpdate, nextUpdate: thisUpdate + 10000, fetchedAt: thisUpdate, size: 100 });
    const lookup = (key, now, ttl = -1, maxBytes = 1000) => cache.lookup(key, 4, ttl, maxBytes, now, debug);
    assert.equal(lookup('a', 1000), undefined);
    assert.equal(cache.store('a', fields('a', 'x', 1000), 4, -1, 1000, debug), true);
    assert.equal(lookup('a', 1500).listed, false);
    // Expiry at nextUpdate makes the entry stale: no answer, still a candidate.
    assert.equal(lookup('a', 11000), undefined);
    assert.ok(events.some(x => (x.event === 'CRL result cache stale') && (x.reason === 'CRL nextUpdate')));
    assert.deepEqual(cache.candidates('x', 'b', 4, -1).map(([key]) => key), [ 'a' ]);
    assert.deepEqual(cache.candidates('x', 'a', 4, -1), []);
    assert.deepEqual(cache.candidates('y', 'b', 4, -1), []);
    // A refresh from a newer CRL makes it fresh again.
    assert.equal(cache.store('a', fields('a', 'x', 12000, true), 4, -1, 12000, debug, false), true);
    assert.equal(lookup('a', 12500).listed, true);
    // An older CRL never replaces a newer result; the same CRL may.
    assert.equal(cache.store('a', fields('a', 'x', 11000, false), 4, -1, 12600, debug), false);
    assert.ok(events.some(x => (x.event === 'CRL result cache store skipped') && /newer CRL/.test(x.reason)));
    assert.equal(lookup('a', 12700).listed, true);
    assert.equal(cache.store('a', fields('a', 'x', 12000, false), 4, -1, 12800, debug), true);
    assert.equal(lookup('a', 12900).listed, false);
    // Caller TTL and size limit make an entry stale, not gone.
    assert.equal(lookup('a', 14000, 1), undefined);
    assert.ok(events.some(x => (x.event === 'CRL result cache stale') && (x.reason === 'caller TTL')));
    assert.equal(lookup('a', 14000, -1, 99), undefined);
    assert.ok(events.some(x => (x.event === 'CRL result cache stale') && (x.reason === 'exceeds maxCrlBytes')));
    assert.equal(lookup('a', 14000).listed, false);
    // Stale candidates are dropped after a day without lookups.
    const staleAt = 12000 + 10000;
    assert.equal(lookup('a', staleAt + 1), undefined);
    cache.prune(4, staleAt + 1 + STALE_CANDIDATE_LIFETIME, debug);
    assert.equal(cache.candidates('x', 'b', 4, -1).length, 1);
    cache.prune(4, staleAt + 2 + STALE_CANDIDATE_LIFETIME, debug);
    assert.equal(cache.candidates('x', 'b', 4, -1).length, 0);
    assert.ok(events.some(x => (x.event === 'CRL result cache candidate dropped') && (x.reason === 'unused')));
});

test('per-certificate CRL results: refreshes are not uses, and the cache can be disabled', function() {
    const { CrlResultCache } = require('../cache');
    const cache = new CrlResultCache();
    const fields = (id, thisUpdate = 1000) => ({ issuerId: 'i', certificateId: id, url: 'http://ca.example/x.crl', group: 'x',
        serial: Buffer.from(id), isCA: false, urls: [], listed: false, thisUpdate, nextUpdate: thisUpdate + 100000,
        fetchedAt: thisUpdate, size: 1 });
    cache.store('a', fields('a'), 2, -1, 1000);
    cache.store('b', fields('b'), 2, -1, 1001);
    // Refreshing a does not make it recently used, so storing c evicts a.
    cache.store('a', fields('a', 1002), 2, -1, 1002, undefined, false);
    cache.store('c', fields('c'), 2, -1, 1003);
    assert.equal(cache.lookup('a', 2, -1, 10, 1004), undefined);
    assert.deepEqual(cache.candidates('x', 'z', 2, -1).map(([key]) => key).sort(), [ 'b', 'c' ]);
    // A lookup is a use, even of a stale entry, and keeps it over others.
    cache.lookup('b', 2, -1, 10, 1005);
    cache.store('d', fields('d'), 2, -1, 1006);
    assert.deepEqual(cache.candidates('x', 'z', 2, -1).map(([key]) => key).sort(), [ 'b', 'd' ]);
    // Expiry is the earlier of nextUpdate and the TTL.
    cache.store('e', fields('e', 2000), 8, 1, 2000);
    assert.notEqual(cache.lookup('e', 8, -1, 10, 2999), undefined);
    assert.equal(cache.lookup('e', 8, -1, 10, 3000), undefined);
    for (const [size, ttl] of [ [ 0, -1 ], [ -1, -1 ], [ 8, 0 ] ]) {
        const disabled = new CrlResultCache();
        assert.equal(disabled.store('a', fields('a'), size, ttl, 1000), false);
        assert.equal(disabled.lookup('a', size, ttl, 10, 1000), undefined);
        assert.deepEqual(disabled.candidates('x', 'z', size, ttl), []);
    }
    cache.remove('d');
    assert.equal(cache.lookup('d', 2, -1, 10, 1007), undefined);
});

test('trFetchWarningCb must be a function and is removed before system fetch', function() {
    for (const cb of [ () => {}, function() {}, async function() {}, class Warned {} ]) {
        const result = splitOptions({ trFetchWarningCb: cb, method: 'GET' });
        assert.equal(result.warningCb, cb);
        assert.deepEqual(result.fetchOptions, { method: 'GET' });
    }
    for (const cb of [ undefined, null ]) {
        assert.equal(splitOptions({ trFetchWarningCb: cb }).warningCb, undefined);
    }
    for (const cb of [ 0, 1, 'console.log', {}, [], true, Symbol('cb') ]) {
        assert.throws(() => splitOptions({ trFetchWarningCb: cb }), /trFetchWarningCb must be a function, null or undefined/);
    }
});

test('warning callbacks are fire and forget: never awaited, and their failures only reported', async function(t) {
    const { callbackFireAndForget } = require('../errors');
    const reported = [];
    t.mock.method(console, 'warn', error => reported.push(error));
    const calls = [];
    const result = callbackFireAndForget((...args) => calls.push(args), 'a', 1);
    // The callback starts at once; its outcome is never waited for.
    assert.equal(result, undefined);
    assert.deepEqual(calls, [ [ 'a', 1 ] ]);
    let settled = false;
    callbackFireAndForget(() => new Promise(resolve => setTimeout(resolve, 50)).then(() => {
        settled = true;
    }));
    assert.equal(settled, false);
    const thrown = new Error('thrown');
    const rejected = new Error('rejected');
    assert.doesNotThrow(() => callbackFireAndForget(() => {
        throw thrown;
    }));
    callbackFireAndForget(async () => {
        throw rejected;
    });
    callbackFireAndForget('not a function');
    callbackFireAndForget(class NotCallable {});
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(reported.length, 4);
    assert.ok(reported.includes(thrown) && reported.includes(rejected));
    assert.equal(reported.filter(x => /Callback not callable/.test(x.message)).length, 1);
    assert.equal(reported.filter(x => (x instanceof TypeError) && ! /Callback not callable/.test(x.message)).length, 1);
});

test('applyPolicy delivers warnings to the callback instead of process warnings', async function(t) {
    const { applyPolicy, TrFetchCrlError, TrFetchOcspError } = require('../errors');
    const emitted = [];
    t.mock.method(process, 'emitWarning', warning => emitted.push(warning));
    const delivered = [];
    const cb = warning => delivered.push(warning);
    const crl = () => new TrFetchCrlError('invalidCrl', 'bad CRL', { hostname: 'example.com', serialNumber: '2A' });
    const ocsp = () => new TrFetchOcspError('rejectedCertificate', 'unknown status', { hostname: 'example.com', ocspStatus: 'unknown' });
    applyPolicy({ invalidCrl: 'warn' }, crl(), undefined, cb);
    applyPolicy({ rejectedCertificate: 'warn' }, ocsp(), undefined, cb);
    applyPolicy({ invalidCrl: 'ignore' }, crl(), undefined, cb);
    assert.throws(() => applyPolicy({ invalidCrl: 'reject' }, crl(), undefined, cb), { code: 'TR_FETCH_CRL_INVALID' });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(emitted.length, 0);
    assert.deepEqual(delivered.map(x => [ x.name, x.code, x.message, x.hostname ]), [
        [ 'TrFetchCrlWarning', 'TR_FETCH_CRL_INVALID', 'trFetch: bad CRL', 'example.com' ],
        [ 'TrFetchOcspWarning', 'TR_FETCH_OCSP_CERTIFICATE_REJECTED', 'trFetch: unknown status', 'example.com' ]
    ]);
    assert.equal(delivered[0].serialNumber, '2A');
    assert.equal(delivered[1].ocspStatus, 'unknown');
    assert.ok(delivered[0] instanceof TrFetchCrlError);
    applyPolicy({ invalidCrl: 'warn' }, crl());
    assert.equal(emitted.length, 1);
    assert.equal(emitted[0].name, 'TrFetchCrlWarning');
});

test('OCSP cache size and TTL are OCSP policy settings with CRL-like validation', function() {
    assert.equal(splitOptions().ocspPolicy.ocspCacheSize, 1024);
    assert.equal(splitOptions().ocspPolicy.ocspCacheTTL, 86400);
    for (const value of [ -1, 0, 1, 5000 ]) {
        assert.equal(splitOptions({ trFetchOcspPolicy: { ocspCacheSize: value } }).ocspPolicy.ocspCacheSize, value);
    }
    for (const value of [ -1, 0, 60, 86400 ]) {
        assert.equal(splitOptions({ trFetchOcspPolicy: { ocspCacheTTL: value } }).ocspPolicy.ocspCacheTTL, value);
    }
    assert.equal(splitOptions({ trFetchOcspPolicy: { ocspCacheSize: null, ocspCacheTTL: undefined } }).ocspPolicy.ocspCacheSize, 1024);
    for (const value of [ 1.5, '10', true, Infinity ]) {
        assert.throws(() => splitOptions({ trFetchOcspPolicy: { ocspCacheSize: value } }), /trFetchOcspPolicy\.ocspCacheSize must be a safe integer/);
    }
    for (const value of [ -2, 1.5, '1800', Infinity ]) {
        assert.throws(() => splitOptions({ trFetchOcspPolicy: { ocspCacheTTL: value } }),
                      /trFetchOcspPolicy\.ocspCacheTTL must be -1 or a nonnegative safe integer/);
    }
    for (const key of [ 'ocspCacheSize', 'ocspCacheTTL' ]) {
        assert.throws(() => splitOptions({ trFetchCrlPolicy: { [key]: 1 } }), /Unknown trFetchCrlPolicy property/);
    }
});

test('the expiring cache reports its own label, and CRL cache events are unchanged', function() {
    const { ExpiringCache } = require('../cache');
    for (const [cache, label] of [ [ new ExpiringCache(), 'CRL cache' ], [ new ExpiringCache('OCSP cache', key => ({ key })), 'OCSP cache' ] ]) {
        const events = [];
        const debug = event => events.push(event);
        assert.equal(cache.get('i:http://x/', 8, 60, 1000, debug), undefined);
        cache.set('i:http://x/', 'value', 100000, 1000, 8, 60, 1000, debug);
        assert.equal(cache.get('i:http://x/', 8, 60, 2000, debug), 'value');
        assert.equal(cache.get('i:http://x/', 8, 60, 61000, debug), undefined);
        assert.deepEqual(events, [ 'miss', 'stored', 'hit', 'expired', 'miss' ].map(x => `${label} ${x}`));
    }
});

test('trFetchCertificateRevocationPolicy: strategy and noRevocationStatus', function() {
    assert.deepEqual(splitOptions().revocationPolicy, { strategy: 'ocsp-first', noRevocationStatus: 'ignore' });
    for (const strategy of [ 'both', 'ocsp-first', 'crl-first' ]) {
        assert.equal(splitOptions({ trFetchCertificateRevocationPolicy: { strategy } }).revocationPolicy.strategy, strategy);
    }
    for (const noRevocationStatus of [ 'ignore', 'warn', 'reject' ]) {
        const result = splitOptions({ trFetchCertificateRevocationPolicy: { noRevocationStatus } });
        assert.equal(result.revocationPolicy.noRevocationStatus, noRevocationStatus);
        assert.deepEqual(result.fetchOptions, {});
    }
    for (const strategy of [ 'either', 'OCSP-first', 'ocsp', '', 1 ]) {
        assert.throws(() => splitOptions({ trFetchCertificateRevocationPolicy: { strategy } }),
                      /trFetchCertificateRevocationPolicy\.strategy must be both, ocsp-first or crl-first/);
    }
    for (const noRevocationStatus of [ 'allow', '', true ]) {
        assert.throws(() => splitOptions({ trFetchCertificateRevocationPolicy: { noRevocationStatus } }),
                      /noRevocationStatus must be ignore, warn or reject/);
    }
    for (const value of [ 'both', [], 1, true ]) {
        assert.throws(() => splitOptions({ trFetchCertificateRevocationPolicy: value }), /must be an object/);
    }
    for (const key of [ 'disabled', 'missingOcspUri', 'crlCacheSize', 'typo' ]) {
        assert.throws(() => splitOptions({ trFetchCertificateRevocationPolicy: { [key]: 'ignore' } }),
                      /Unknown trFetchCertificateRevocationPolicy property/);
    }
    for (const key of [ 'strategy', 'noRevocationStatus' ]) {
        assert.throws(() => splitOptions({ trFetchCrlPolicy: { [key]: 'both' } }), /Unknown trFetchCrlPolicy property/);
    }
});

test('TrFetchRevocationError is the base of CRL and OCSP errors and reports noRevocationStatus', function() {
    const trFetch = require('..');
    const { TrFetchRevocationError, TrFetchCrlError, TrFetchOcspError } = trFetch;
    const error = new TrFetchRevocationError('noRevocationStatus', 'no status', { hostname: 'example.com' });
    assert.equal(error.name, 'TrFetchRevocationError');
    assert.equal(error.code, 'TR_FETCH_REVOCATION_STATUS_UNAVAILABLE');
    assert.equal(error.message, 'trFetch: no status');
    assert.ok(! (error instanceof TrFetchCrlError) && ! (error instanceof TrFetchOcspError));
    assert.ok(new TrFetchCrlError('invalidCrl', 'x') instanceof TrFetchRevocationError);
    assert.ok(new TrFetchOcspError('rejectedCertificate', 'x') instanceof TrFetchRevocationError);
});

test('null and undefined mean the default for every trFetch option and policy setting', function() {
    const defaults = splitOptions();
    const policies = { trFetchCrlPolicy: 'policy', trFetchOcspPolicy: 'ocspPolicy', trFetchCertificateRevocationPolicy: 'revocationPolicy' };
    for (const empty of [ undefined, null ]) {
        // Whole options, including every policy object.
        for (const key of [ 'trFetchDebug', 'trFetchWarningCb', 'trFetchCrlOverride', 'trFetchCrlDistributionPointOverride',
                            'trFetchOcspUriOverride', ...Object.keys(policies) ]) {
            const result = splitOptions({ [key]: empty, method: 'GET' });
            assert.deepEqual({ ...result, fetchOptions: undefined }, { ...defaults, fetchOptions: undefined }, `${key}: ${empty}`);
            assert.deepEqual(result.fetchOptions, { method: 'GET' }, `${key}: ${empty}`);
        }
        // Every setting of every policy object, one at a time and all at once.
        for (const [option, field] of Object.entries(policies)) {
            const keys = Object.keys(defaults[field]);
            assert.ok(keys.length >= 2);
            for (const key of keys) {
                assert.deepEqual(splitOptions({ [option]: { [key]: empty } })[field], defaults[field], `${option}.${key}: ${empty}`);
            }
            assert.deepEqual(splitOptions({ [option]: Object.fromEntries(keys.map(key => [ key, empty ])) })[field], defaults[field]);
            // Unknown settings are rejected even when null.
            assert.throws(() => splitOptions({ [option]: { typo: empty } }), new RegExp(`Unknown ${option} property: typo`));
        }
        // Unknown options are rejected even when null.
        assert.throws(() => splitOptions({ trFetchTypo: empty }), /Unknown trFetch option: trFetchTypo/);
    }
    // A null override does not conflict with the other override.
    assert.equal(splitOptions({ trFetchCrlOverride: null, trFetchCrlDistributionPointOverride: 'http://ca.example/x.crl' }).distributionPoint,
                 'http://ca.example/x.crl');
});
