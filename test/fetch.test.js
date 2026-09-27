'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const { once } = require('node:events');
const fetch = require('..');
const pki = require('pkijs');
const fixtures = require('./fixtures');

const testDebug = /^(y|yes|true|1)$/i.test(process.env.TR_FETCH_TEST_DEBUG ?? '');
// Explicit options still win so tests of disabled/default debugging stay valid.
const trFetch = Object.assign(function(input, options) {
    return fetch(input, testDebug ? { trFetchDebug: true, ...options } : options);
}, fetch);

let ca, goodCrl, revokedCrl, crlServer, crlBase, crlRequests;
const routes = new Map();
const originalCAs = tls.getCACertificates('default');

test.before(async function() {
    ca = await fixtures.certificate({ ca: true });
    tls.setDefaultCACertificates([ ...originalCAs, ca.pem ]);
    goodCrl = await fixtures.crl(ca);
    revokedCrl = await fixtures.crl(ca, { serials: [ 42 ] });
    crlRequests = [];
    crlServer = http.createServer(function(req, res) {
        crlRequests.push({ url: req.url, headers: req.headers, method: req.method });
        const route = routes.get(req.url);
        if (typeof(route) === 'function') {
            Promise.resolve(route(req, res)).catch(error => res.destroy(error));
        } else if (route) {
            res.end(route);
        } else {
            res.writeHead(404).end();
        }
    });
    crlServer.listen(0, '127.0.0.1');
    await once(crlServer, 'listening');
    crlBase = `http://127.0.0.1:${crlServer.address().port}`;
    routes.set('/good', goodCrl.der);
    routes.set('/revoked', revokedCrl.pem);
});

test.after(async function() {
    tls.setDefaultCACertificates(originalCAs);
    crlServer.closeAllConnections();
    await new Promise(resolve => crlServer.close(resolve));
});

async function endpoint(t, options = {}, handler) {
    const leaf = await fixtures.certificate({ issuer: ca, serial: 42, ...options });
    let hits = 0;
    const server = https.createServer({ cert: leaf.pem + (options.chain ?? ''), key: leaf.key }, function(req, res) {
        hits++;
        if (handler) {
            handler(req, res);
        } else {
            res.end('ok');
        }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(async function() {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
    });
    return { url: `https://localhost:${server.address().port}`, leaf, hits: () => hits };
}

function crlError(code, message) {
    return function(error) {
        assert.ok(error instanceof trFetch.TrFetchCrlError);
        assert.equal(error.code, code);
        assert.match(error.message, message);
        assert.equal(error.serialNumber, '2A');
        return true;
    };
}

function captureDebug(t) {
    const events = [];
    const write = process.stderr.write.bind(process.stderr);
    t.mock.method(process.stderr, 'write', function(line) {
        const match = String(line).match(/^\[trFetch debug #(\d+)\] ([^{]+) (\{.*\})\n$/);
        assert.ok(match, `Expected one debug event per line: ${line}`);
        events.push({ id: match[1], event: match[2], ...JSON.parse(match[3]) });
        return testDebug ? write(line) : true;
    });
    return events;
}

test('debug traces CRL/OCSP discovery, authenticated results and cache use without logging request secrets', async function(t) {
    routes.set('/debug-crl?token=crl-secret', goodCrl.der);
    routes.set('/debug-ocsp?token=ocsp-secret', ocspRoute(ca));
    const server = await endpoint(t, {
        urls: [ crlBase + '/debug-crl?token=crl-secret' ], ocspUrls: [ crlBase + '/debug-ocsp?token=ocsp-secret' ]
    });
    const events = captureDebug(t);
    for (const trFetchDebug of [ undefined, false ]) {
        await (await trFetch(server.url, { trFetchDebug, trFetchCrlCacheTTL: 0 })).text();
    }
    assert.equal(events.length, 0);
    await (await trFetch(server.url + '/?token=application-secret', {
        trFetchDebug: true, method: 'POST', body: 'body-secret', headers: { authorization: 'Bearer header-secret' }
    })).text();
    for (const event of [ 'CRL distribution point detected in certificate', 'CRL cache miss', 'CRL fetched', 'CRL parsed',
                          'CRL cache stored', 'OCSP URI detected in certificate', 'OCSP response fetched', 'OCSP response parsed',
                          'Revocation checks completed; connection allowed' ]) {
        assert.ok(events.some(x => x.event === event), event);
    }
    for (const [event, result, policy] of [ [ 'CRL serial lookup completed', 'not listed', 'revokedCertificate' ],
                                            [ 'OCSP check completed', 'good', 'rejectedCertificate' ] ]) {
        const found = events.find(x => x.event === event);
        assert.equal(found.hostname, 'localhost');
        assert.equal(found.certificate, 'leaf');
        assert.equal(found.depth, 0);
        assert.equal(found.serial, '2A');
        assert.equal(found.result, result);
        assert.equal(found.authenticated, true);
        assert.equal(found.policy, policy);
        assert.equal(found.configuredAction, 'reject');
        assert.equal(found.action, 'continue');
    }
    const firstId = events[0].id;
    assert.ok(events.every(x => x.id === firstId));
    assert.doesNotMatch(JSON.stringify(events), /crl-secret|ocsp-secret|application-secret|body-secret|header-secret/);
    events.length = 0;
    await (await trFetch(server.url, { trFetchDebug: true })).text();
    assert.notEqual(events[0].id, firstId);
    assert.ok(events.some(x => x.event === 'CRL cache hit'));
    assert.ok(! events.some(x => x.event === 'CRL fetched'));
    assert.ok(events.some(x => x.event === 'CRL serial lookup completed'));
    assert.ok(events.some(x => x.event === 'OCSP response fetched'));
});

test('debug shows CRL and OCSP rejection and warning/ignore policies without changing enforcement', async function(t) {
    const server = await endpoint(t);
    routes.set('/debug-ocsp-revoked', ocspRoute(ca, { status: 'revoked' }));
    const events = captureDebug(t);
    const warnings = [];
    t.mock.method(process, 'emitWarning', warning => warnings.push(warning));
    await assert.rejects(trFetch(server.url, { trFetchDebug: true, trFetchCrlOverride: revokedCrl.der }), {
        code: 'TR_FETCH_CERTIFICATE_REVOKED'
    });
    assert.equal(server.hits(), 0);
    assert.ok(events.some(x => x.event === 'CRL serial lookup completed' && x.result === 'revoked' && x.action === 'reject'));
    assert.ok(events.some(x => x.event === 'CRL policy applied' && x.action === 'reject'));
    events.length = 0;
    await assert.rejects(trFetch(server.url, { trFetchDebug: true, trFetchOcspUriOverride: crlBase + '/debug-ocsp-revoked' }), {
        code: 'TR_FETCH_OCSP_CERTIFICATE_REJECTED'
    });
    assert.equal(server.hits(), 0);
    assert.ok(events.some(x => x.event === 'OCSP URI override selected'));
    assert.ok(events.some(x => x.event === 'OCSP check completed' && x.result === 'revoked' && x.action === 'reject'));
    assert.ok(events.some(x => x.event === 'OCSP policy applied' && x.action === 'reject'));
    events.length = 0;
    await (await trFetch(server.url, {
        trFetchDebug: true, trFetchCrlOverride: revokedCrl.der, trFetchCrlPolicy: { revokedCertificate: 'warn' },
        trFetchOcspUriOverride: crlBase + '/debug-ocsp-revoked', trFetchOcspPolicy: { rejectedCertificate: 'ignore' }
    })).text();
    assert.equal(server.hits(), 1);
    assert.equal(warnings.length, 1);
    assert.ok(events.some(x => x.event === 'CRL policy applied' && x.action === 'warn'));
    assert.ok(events.some(x => x.event === 'OCSP policy applied' && x.action === 'ignore'));
});

test('debug identifies intermediate depth and excludes the trust anchor', async function(t) {
    const intermediate = await fixtures.certificate({ issuer: ca, ca: true, serial: 100,
                                                      urls: [ crlBase + '/good' ], ocspUrls: [ crlBase + '/debug-intermediate-ocsp' ] });
    routes.set('/debug-intermediate-ocsp', ocspRoute(ca));
    routes.set('/debug-chain-leaf-crl', (await fixtures.crl(intermediate)).der);
    routes.set('/debug-chain-leaf-ocsp', ocspRoute(intermediate));
    const server = await endpoint(t, { issuer: intermediate, chain: intermediate.pem,
                                       urls: [ crlBase + '/debug-chain-leaf-crl' ], ocspUrls: [ crlBase + '/debug-chain-leaf-ocsp' ] });
    const events = captureDebug(t);
    await (await trFetch(server.url, { trFetchDebug: true, trFetchCrlCheckDepth: 'full-chain', trFetchOcspCheckDepth: 'full-chain' })).text();
    for (const event of [ 'CRL distribution point detected in certificate', 'CRL serial lookup completed',
                          'OCSP URI detected in certificate', 'OCSP check completed' ]) {
        const found = events.filter(x => x.event === event);
        assert.deepEqual(found.map(x => [ x.certificate, x.depth, x.serial ]), [ [ 'leaf', 0, '2A' ], [ 'intermediate CA', 1, '64' ] ]);
    }
    assert.ok(events.some(x => x.event === 'Trust anchor excluded from revocation checks' && x.depth === 2));
});

test('debug is isolated between concurrent fetches and reports disabled checks', async function(t) {
    const server = await endpoint(t);
    const events = captureDebug(t);
    await Promise.all([ '/debug-one', '/quiet', '/debug-two' ].map(async function(path) {
        await (await trFetch(server.url + path, {
            trFetchDebug: path !== '/quiet', trFetchCrlPolicy: { disabled: true }, trFetchOcspPolicy: { disabled: true }
        })).text();
    }));
    assert.equal(server.hits(), 3);
    assert.equal(new Set(events.map(x => x.id)).size, 2);
    assert.equal(events.length, 4);
    assert.ok(events.every(x => ! x.url.includes('/quiet')));
    assert.ok(events.filter(x => x.event === 'Verification configured').every(x => x.crl === 'disabled' && x.ocsp === 'disabled'));
});

test('native response, URL and Request inputs, POST body and headers survive wrapping', async function(t) {
    const server = await endpoint(t, { urls: [ crlBase + '/good' ] }, async function(req, res) {
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ method: req.method, body: Buffer.concat(chunks).toString(), header: req.headers['x-test'] }));
    });
    const request = new Request(new URL(server.url), { method: 'POST', body: 'payload', headers: { 'x-test': 'value' } });
    const response = await trFetch(request);
    assert.ok(response instanceof Response);
    assert.deepEqual(await response.json(), { method: 'POST', body: 'payload', header: 'value' });
    assert.equal(server.hits(), 1);
});

test('revoked certificate rejects before HTTP headers or body are sent', async function(t) {
    const server = await endpoint(t, { urls: [ crlBase + '/revoked' ] });
    await assert.rejects(trFetch(server.url, { method: 'POST', body: 'secret' }), crlError('TR_FETCH_CERTIFICATE_REVOKED', /Revoked server certificate/));
    assert.equal(server.hits(), 0);
});

test('missing distribution point: ignore by default, reject or warn on request', async function(t) {
    const server = await endpoint(t);
    assert.equal(await (await trFetch(server.url)).text(), 'ok');
    await assert.rejects(trFetch(server.url, { trFetchCrlPolicy: { missingCrlDistributionPoint: 'reject' } }), crlError('TR_FETCH_CRL_MISSING_DISTRIBUTION_POINT', /Missing CRL distribution point/));
    const warnings = [];
    t.mock.method(process, 'emitWarning', warning => warnings.push(warning));
    await (await trFetch(server.url, { trFetchCrlPolicy: { missingCrlDistributionPoint: 'warn' } })).text();
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].name, 'TrFetchCrlWarning');
    assert.equal(warnings[0].code, 'TR_FETCH_CRL_MISSING_DISTRIBUTION_POINT');
});

test('warn and ignore for revocation remain distinct from invalid CRL policy', async function(t) {
    const server = await endpoint(t, { urls: [ crlBase + '/revoked' ] });
    const warnings = [];
    t.mock.method(process, 'emitWarning', warning => warnings.push(warning));
    await (await trFetch(server.url, { trFetchCrlPolicy: { revokedCertificate: 'warn' } })).text();
    assert.equal(warnings[0].code, 'TR_FETCH_CERTIFICATE_REVOKED');
    await (await trFetch(server.url, { trFetchCrlPolicy: { revokedCertificate: 'ignore' } })).text();
    assert.equal(warnings.length, 1);
    await assert.rejects(trFetch(server.url, { trFetchCrlPolicy: { invalidCrl: 'ignore' } }), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
});

test('network failures and forbidden schemes use unreachable policy', async function(t) {
    for (const url of [ crlBase + '/missing', 'file:///tmp/no.crl', 'ldap://localhost/cn=CA' ]) {
        const server = await endpoint(t, { urls: [ url ] });
        await assert.rejects(trFetch(server.url), crlError('TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT', /Unreachable CRL distribution point/));
        assert.equal(server.hits(), 0);
        await (await trFetch(server.url, { trFetchCrlPolicy: { unreachableCrlDistributionPoint: 'ignore' } })).text();
    }
});

test('malformed, expired, not-yet-valid and incorrectly signed CRLs are invalid', async function(t) {
    const server = await endpoint(t);
    const other = await fixtures.certificate({ ca: true, serial: 9 });
    const cases = [
        [ Buffer.from('garbage'), /ASN.1|schema/ ],
        [ (await fixtures.crl(ca, { start: Date.now() - 7200000, end: Date.now() - 3600000 })).der, /expired/ ],
        [ (await fixtures.crl(ca, { start: Date.now() + 60000 })).der, /not yet valid/ ],
        [ (await fixtures.crl(ca, { missingNext: true })).der, /nextUpdate/ ],
        [ (await fixtures.crl(other)).der, /issuer/ ],
        [ (await fixtures.crl(ca, { signingKey: other.keys.privateKey })).der, /signature verification failed/ ]
    ];
    for (const [bytes, message] of cases) {
        await assert.rejects(trFetch(server.url, { trFetchCrlOverride: bytes }), crlError('TR_FETCH_CRL_INVALID', message));
    }
    assert.equal(server.hits(), 0);
    await (await trFetch(server.url, { trFetchCrlOverride: 'bad', trFetchCrlPolicy: { invalidCrl: 'ignore' } })).text();
});

test('overrides replace advertised distribution points and remain authenticated', async function(t) {
    const server = await endpoint(t, { urls: [ 'file:///no-crl' ] });
    await (await trFetch(server.url, { trFetchCrlDistributionPointOverride: crlBase + '/good' })).text();
    for (const value of [ goodCrl.pem, goodCrl.der, new Uint8Array(goodCrl.der) ]) {
        await (await trFetch(server.url, { trFetchCrlOverride: value })).text();
    }
    await assert.rejects(trFetch(server.url, { trFetchCrlOverride: revokedCrl.der }), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    await assert.rejects(trFetch(server.url, { trFetchCrlDistributionPointOverride: 'file:///tmp/crl' }), { code: 'TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT' });
});

test('default TLS trust, validity and hostname checks cannot be relaxed by CRL policies', async function(t) {
    const untrustedCA = await fixtures.certificate({ ca: true, serial: 10 });
    const untrusted = await endpoint(t, { issuer: untrustedCA });
    const expired = await endpoint(t, { expired: true });
    const valid = await endpoint(t);
    const ignore = { trFetchCrlPolicy: {
        missingCrlDistributionPoint: 'ignore', unreachableCrlDistributionPoint: 'ignore', invalidCrl: 'ignore', revokedCertificate: 'ignore'
    } };
    for (const [server, url] of [ [ untrusted, untrusted.url ], [ expired, expired.url ], [ valid, valid.url.replace('localhost', '127.0.0.1') ] ]) {
        await assert.rejects(trFetch(url, ignore), error => (error instanceof TypeError) && !! error.cause);
        assert.equal(server.hits(), 0);
    }
});

test('maxCrlBytes limits CRL downloads, override data and cached CRLs, and can be raised', async function(t) {
    const big = await fixtures.bulkCrl(ca, 800000, { serials: [ 42 ] });
    assert.ok(big.length > 16 * 1024 * 1024);
    routes.set('/big.crl', big);
    const server = await endpoint(t, { urls: [ crlBase + '/big.crl' ] });
    await assert.rejects(trFetch(server.url), crlError('TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT',
        /CRL download exceeds maxCrlBytes \(16777216 bytes\)/));
    const raised = { maxCrlBytes: 32 * 1024 * 1024 };
    await assert.rejects(trFetch(server.url, { trFetchCrlPolicy: raised }), crlError('TR_FETCH_CERTIFICATE_REVOKED', /Revoked/));
    // Now cached; the cache must not let it bypass a lower limit.
    const events = captureDebug(t);
    await assert.rejects(trFetch(server.url, { trFetchDebug: true }), { code: 'TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT' });
    assert.ok(events.some(x => (x.event === 'CRL cache entry not used') && (x.maxCrlBytes === 16777216)));
    t.mock.restoreAll();
    await assert.rejects(trFetch(server.url, { trFetchCrlPolicy: raised }), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    const small = await endpoint(t);
    await assert.rejects(trFetch(small.url, { trFetchCrlOverride: goodCrl.der, trFetchCrlPolicy: { maxCrlBytes: goodCrl.der.length - 1 } }),
        crlError('TR_FETCH_CRL_INVALID', /CRL exceeds maxCrlBytes/));
    await (await trFetch(small.url, { trFetchCrlOverride: goodCrl.der, trFetchCrlPolicy: { maxCrlBytes: goodCrl.der.length } })).text();
});

test('a cached revocation list answers for other certificates of the same issuer without a download', async function(t) {
    routes.set('/shared', revokedCrl.der);
    const count = () => crlRequests.filter(x => x.url === '/shared').length;
    const good = await endpoint(t, { urls: [ crlBase + '/shared' ], serial: 41 });
    const revoked = await endpoint(t, { urls: [ crlBase + '/shared' ], serial: 42 });
    const events = captureDebug(t);
    await (await trFetch(good.url, { trFetchDebug: true, trFetchOcspPolicy: { disabled: true } })).text();
    assert.equal(count(), 1);
    const indexed = events.find(x => x.event === 'CRL authenticated and indexed');
    assert.equal(indexed.serials, 1);
    assert.equal(indexed.indexBytes, 1);
    events.length = 0;
    await assert.rejects(trFetch(revoked.url, { trFetchDebug: true, trFetchOcspPolicy: { disabled: true } }),
        crlError('TR_FETCH_CERTIFICATE_REVOKED', /Revoked server certificate/));
    assert.equal(count(), 1);
    assert.equal(revoked.hits(), 0);
    assert.ok(events.some(x => x.event === 'CRL cache hit'));
    assert.ok(! events.some(x => [ 'CRL fetched', 'CRL parsed', 'CRL authenticated and indexed' ].includes(x.event)));
    t.mock.restoreAll();
    await (await trFetch(good.url, { trFetchOcspPolicy: { disabled: true } })).text();
    assert.equal(count(), 1);
    assert.equal(good.hits(), 2);
});

const byCertificate = (options = {}) => ({ ...options, trFetchCrlPolicy: { crlCacheScope: 'certificate', ...options.trFetchCrlPolicy },
                                           trFetchOcspPolicy: { disabled: true } });

test('certificate scope streams the CRL, caches a result per certificate and classifies failures', async function(t) {
    routes.set('/cs-basic', revokedCrl.der);
    const count = () => crlRequests.filter(x => x.url === '/cs-basic').length;
    const revoked = await endpoint(t, { urls: [ crlBase + '/cs-basic' ] });
    const good = await endpoint(t, { urls: [ crlBase + '/cs-basic' ], serial: 41 });
    const events = captureDebug(t);
    await assert.rejects(trFetch(revoked.url, byCertificate({ trFetchDebug: true })), crlError('TR_FETCH_CERTIFICATE_REVOKED', /Revoked/));
    assert.equal(revoked.hits(), 0);
    assert.ok(events.some(x => (x.event === 'Verification configured') && (x.crlCacheScope === 'certificate')));
    assert.ok(events.some(x => (x.event === 'CRL authenticated while streaming') && (x.revokedEntries === 1)));
    assert.ok(! events.some(x => [ 'CRL fetched', 'CRL parsed', 'CRL authenticated and indexed' ].includes(x.event)));
    t.mock.restoreAll();
    assert.equal(count(), 1);
    // The revoked result is cached too.
    await assert.rejects(trFetch(revoked.url, byCertificate()), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    assert.equal(count(), 1);
    // Another certificate is a separate entry, checked in its own download,
    // which also refreshes the first one.
    await (await trFetch(good.url, byCertificate())).text();
    assert.equal(count(), 2);
    await (await trFetch(good.url, byCertificate())).text();
    assert.equal(count(), 2);
    assert.equal(good.hits(), 2);
    // PEM CRLs stream as well.
    const pem = await endpoint(t, { urls: [ crlBase + '/revoked' ] });
    await assert.rejects(trFetch(pem.url, byCertificate()), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    // Content errors are invalid CRLs; transfer errors are unreachable.
    routes.set('/cs-garbage', Buffer.from('garbage that is not a CRL at all'));
    const tampered = Buffer.from(goodCrl.der);
    tampered[tampered.length - 5] ^= 1;
    routes.set('/cs-tampered', tampered);
    for (const [path, code, message] of [
        [ '/cs-garbage', 'TR_FETCH_CRL_INVALID', /Invalid CRL/ ],
        [ '/cs-tampered', 'TR_FETCH_CRL_INVALID', /signature verification failed/ ],
        [ '/cs-missing', 'TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT', /HTTP 404/ ]
    ]) {
        const server = await endpoint(t, { urls: [ crlBase + path ] });
        await assert.rejects(trFetch(server.url, byCertificate()), crlError(code, message), path);
        assert.equal(server.hits(), 0);
    }
    const limited = await endpoint(t, { urls: [ crlBase + '/cs-basic' ], serial: 44 });
    await assert.rejects(trFetch(limited.url, byCertificate({ trFetchCrlPolicy: { maxCrlBytes: 50 } })), error =>
        (error.code === 'TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT') && /exceeds maxCrlBytes \(50 bytes\)/.test(error.message));
    // Override data is checked directly, bypassing the cached result.
    await assert.rejects(trFetch(revoked.url, byCertificate({ trFetchCrlOverride: revokedCrl.der })), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    await (await trFetch(revoked.url, byCertificate({ trFetchCrlOverride: goodCrl.der }))).text();
    assert.equal(revoked.hits(), 1);
    // The size-limited check above made one request; the overrides none.
    assert.equal(count(), 3);
});

test('certificate scope: one download refreshes all cached certificates of the same CRL, including stale ones', async function(t) {
    routes.set('/cs-refresh', goodCrl.der);
    const count = () => crlRequests.filter(x => x.url === '/cs-refresh').length;
    const [a, b, c] = await Promise.all([ 51, 52, 53 ].map(serial => endpoint(t, { urls: [ crlBase + '/cs-refresh' ], serial })));
    await (await trFetch(a.url, byCertificate())).text();
    assert.equal(count(), 1);
    // A newer CRL revokes a; checking b downloads it and refreshes a.
    routes.set('/cs-refresh', (await fixtures.crl(ca, { serials: [ 51 ], start: Date.now() })).der);
    const events = captureDebug(t);
    await (await trFetch(b.url, byCertificate({ trFetchDebug: true }))).text();
    assert.equal(count(), 2);
    assert.ok(events.some(x => (x.event === 'CRL authenticated while streaming') && (x.serialsChecked === 2)));
    assert.ok(events.some(x => (x.event === 'CRL result cache refreshed') && (x.listed === true)));
    t.mock.restoreAll();
    await assert.rejects(trFetch(a.url, byCertificate()), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    assert.equal(count(), 2);
    assert.equal(a.hits(), 1);
    // Once stale, entries still name the certificates to check: after c's
    // download, which revokes b, b is answered without a download of its own.
    await new Promise(resolve => setTimeout(resolve, 1100));
    routes.set('/cs-refresh', (await fixtures.crl(ca, { serials: [ 51, 52 ], start: Date.now() })).der);
    await (await trFetch(c.url, byCertificate({ trFetchCrlCacheTTL: 1 }))).text();
    assert.equal(count(), 3);
    await assert.rejects(trFetch(b.url, byCertificate({ trFetchCrlCacheTTL: 1 })), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    await assert.rejects(trFetch(a.url, byCertificate({ trFetchCrlCacheTTL: 1 })), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    assert.equal(count(), 3);
});

test('certificate scope: an older CRL never replaces a newer result, and a changed scope drops candidates', async function(t) {
    const newer = await fixtures.crl(ca, { start: Date.now() - 1000 });
    const older = await fixtures.crl(ca, { serials: [ 61 ], start: Date.now() - 120000 });
    routes.set('/cs-order', newer.der);
    const count = () => crlRequests.filter(x => x.url === '/cs-order').length;
    const [a, b] = await Promise.all([ 61, 62 ].map(serial => endpoint(t, { urls: [ crlBase + '/cs-order' ], serial })));
    await (await trFetch(a.url, byCertificate())).text();
    // A stale mirror serves an older CRL that lists a: b is checked against
    // it, but a keeps its result from the newer CRL.
    routes.set('/cs-order', older.der);
    const events = captureDebug(t);
    await (await trFetch(b.url, byCertificate({ trFetchDebug: true }))).text();
    assert.ok(events.some(x => (x.event === 'CRL result cache store skipped') && /newer CRL/.test(x.reason)));
    t.mock.restoreAll();
    await (await trFetch(a.url, byCertificate())).text();
    assert.equal(count(), 2);
    // A newer CRL that covers only CA certificates: b fails, and a is no
    // longer a candidate.
    const caOnly = fixtures.extension('2.5.29.28', new pki.IssuingDistributionPoint({ onlyContainsCACerts: true }).toSchema(), true);
    routes.set('/cs-order', (await fixtures.crl(ca, { extensions: [ caOnly ], start: Date.now() })).der);
    const c = await endpoint(t, { urls: [ crlBase + '/cs-order' ], serial: 63 });
    const dropped = captureDebug(t);
    await assert.rejects(trFetch(c.url, byCertificate({ trFetchDebug: true })), error =>
        (error.code === 'TR_FETCH_CRL_INVALID') && /scope does not cover/.test(error.message));
    assert.equal(dropped.filter(x => (x.event === 'CRL result cache candidate dropped') && /scope/.test(x.reason)).length, 2);
});

test('CRL cache is shared, TTL zero and nonpositive sizes bypass it', async function(t) {
    routes.set('/cache', goodCrl.der);
    const server = await endpoint(t, { urls: [ crlBase + '/cache' ] });
    const count = () => crlRequests.filter(x => x.url === '/cache').length;
    await (await trFetch(server.url)).text();
    await (await trFetch(server.url)).text();
    assert.equal(count(), 1);
    routes.set('/cache', revokedCrl.der);
    for (const options of [ { trFetchCrlCacheTTL: 0 }, { trFetchCrlCacheSize: 0 }, { trFetchCrlCacheSize: -5 } ]) {
        await assert.rejects(trFetch(server.url, options), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    }
    assert.equal(count(), 4);
});

test('invalid downloaded data is never cached even under ignore policy', async function(t) {
    routes.set('/invalid-cache', 'bad');
    const server = await endpoint(t, { urls: [ crlBase + '/invalid-cache' ] });
    await (await trFetch(server.url, { trFetchCrlPolicy: { invalidCrl: 'ignore' } })).text();
    routes.set('/invalid-cache', revokedCrl.der);
    await assert.rejects(trFetch(server.url), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
});

test('HTTP and HTTPS redirects cannot bypass destination CRL checks', async function(t) {
    const revoked = await endpoint(t, { urls: [ crlBase + '/revoked' ] });
    const redirect = await endpoint(t, { urls: [ crlBase + '/good' ] }, (req, res) => res.writeHead(302, { location: revoked.url }).end());
    await assert.rejects(trFetch(redirect.url), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    assert.equal(revoked.hits(), 0);
    const manual = await trFetch(redirect.url, { redirect: 'manual' });
    assert.equal(manual.status, 302);
    await manual.body.cancel();
    routes.set('/redirect-to-revoked-server', (req, res) => res.writeHead(302, { location: revoked.url }).end());
    await assert.rejects(trFetch(crlBase + '/redirect-to-revoked-server'), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
});

test('CRL redirects validate schemes, do not forward application credentials and can use alternate URLs', async function(t) {
    routes.set('/redirect-local', (req, res) => res.writeHead(302, { location: 'file:///tmp/crl' }).end());
    const bad = await endpoint(t, { urls: [ crlBase + '/redirect-local' ] });
    await assert.rejects(trFetch(bad.url), { code: 'TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT' });
    const fallback = await endpoint(t, { urls: [ crlBase + '/missing', crlBase + '/credentials' ] });
    routes.set('/credentials', goodCrl.der);
    await (await trFetch(fallback.url, { headers: { authorization: 'Bearer secret', cookie: 'secret=1' } })).text();
    const crlRequest = crlRequests.find(x => x.url === '/credentials');
    assert.equal(crlRequest.headers.authorization, undefined);
    assert.equal(crlRequest.headers.cookie, undefined);
});

test('abort during CRL download releases the waiting TLS socket without sending the request', async function(t) {
    let started;
    const downloading = new Promise(resolve => { started = resolve; });
    routes.set('/hang', (req, res) => { started(); });
    const server = await endpoint(t, { urls: [ crlBase + '/hang' ] });
    const controller = new AbortController();
    const pending = trFetch(server.url, { signal: controller.signal });
    const rejected = assert.rejects(pending, error => error === controller.signal.reason);
    await downloading;
    controller.abort(new Error('cancelled by caller'));
    await rejected;
    assert.equal(server.hits(), 0);
});

test('streaming response body remains readable after fetch resolves', async function(t) {
    const server = await endpoint(t, {}, (req, res) => {
        res.write('first');
        setTimeout(() => res.end('second'), 30);
    });
    assert.equal(await (await trFetch(server.url)).text(), 'firstsecond');
});

test('leaf default and numeric/full-chain depth; overrides only replace leaf CRL', async function(t) {
    const intermediate = await fixtures.certificate({ issuer: ca, ca: true, serial: 100, urls: [ crlBase + '/intermediate-revoked' ] });
    routes.set('/intermediate-revoked', (await fixtures.crl(ca, { serials: [ 100 ] })).der);
    const leafCrl = await fixtures.crl(intermediate);
    const server = await endpoint(t, { issuer: intermediate, chain: intermediate.pem });
    for (const depth of [ undefined, 0, 'leaf' ]) {
        await (await trFetch(server.url, { trFetchCrlCheckDepth: depth, trFetchCrlOverride: leafCrl.der })).text();
    }
    for (const depth of [ 1, 2, 'full-chain' ]) {
        await assert.rejects(trFetch(server.url, { trFetchCrlCheckDepth: depth, trFetchCrlOverride: leafCrl.der }), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    }
});

test('full-chain excludes the trust anchor even with missing-DP reject', async function(t) {
    const server = await endpoint(t, { urls: [ crlBase + '/good' ] });
    await (await trFetch(server.url, { trFetchCrlCheckDepth: 'full-chain', trFetchCrlPolicy: { missingCrlDistributionPoint: 'reject' } })).text();
});

test('custom global dispatcher is rejected rather than silently losing its checks', async function() {
    const { Agent, getGlobalDispatcher, setGlobalDispatcher } = require('undici');
    const previous = getGlobalDispatcher();
    const custom = new Agent({ connect: { rejectUnauthorized: false } });
    try {
        setGlobalDispatcher(custom);
        await assert.rejects(trFetch('https://example.com'), /custom or unrecognized global dispatchers/);
    } finally {
        setGlobalDispatcher(previous);
        await custom.close();
    }
});

async function withSystemFetch(replacement, action) {
    const original = globalThis.fetch;
    globalThis.fetch = replacement(original);
    try {
        return await action();
    } finally {
        globalThis.fetch = original;
    }
}

test('replaced system fetch that bypasses the verifying dispatcher fails closed', async function(t) {
    const server = await endpoint(t, { urls: [ crlBase + '/revoked' ] });
    const other = await endpoint(t, { urls: [ crlBase + '/good' ] });
    const bypassed = /did not come through the verifying dispatcher/;
    await assert.rejects(trFetch(server.url), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    // A wrapper that drops the dispatcher would otherwise return the response
    // of a revoked server; the request itself cannot be prevented.
    await withSystemFetch(original => (input, { dispatcher, ...init } = {}) => original(input, init), async function() {
        await assert.rejects(trFetch(server.url), error => (error instanceof TypeError) && bypassed.test(error.message));
        assert.equal(server.hits(), 1);
        assert.equal(await (await trFetch('data:,inline')).text(), 'inline');
    });
    // The final response must also come from a verified connection.
    await withSystemFetch(original => async function(input, init) {
        await (await original(input, init)).text();
        return original(server.url + '/elsewhere');
    }, async function() {
        await assert.rejects(trFetch(other.url), error => (error instanceof TypeError) && bypassed.test(error.message));
    });
    await withSystemFetch(original => (input, init) => original(input, init), async function() {
        assert.equal(await (await trFetch(other.url)).text(), 'ok');
        await assert.rejects(trFetch(server.url), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    });
});

test('CRL downloads that bypass the verifying dispatcher are unreachable', async function(t) {
    const server = await endpoint(t, { urls: [ crlBase + '/good' ] });
    await withSystemFetch(original => function(input, init = {}) {
        const { dispatcher, ...rest } = init;
        return String(input instanceof Request ? input.url : input).startsWith(crlBase) ? original(input, rest) : original(input, init);
    }, async function() {
        await assert.rejects(trFetch(server.url, { trFetchCrlCacheTTL: 0 }),
            crlError('TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT', /did not come through the verifying dispatcher/));
    });
    assert.equal(server.hits(), 0);
});

function ocspRoute(issuer, options = {}) {
    return async function(req, res) {
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        const response = await fixtures.ocsp(issuer, Buffer.concat(chunks), options);
        res.setHeader('content-type', 'application/ocsp-response');
        res.end(response.der);
    };
}

test('OCSP is enabled by default, posts fresh requests and does not forward application credentials', async function(t) {
    routes.set('/ocsp-good', ocspRoute(ca));
    const server = await endpoint(t, { ocspUrls: [ crlBase + '/ocsp-good' ] });
    for (let i = 0; i < 2; i++) {
        await (await trFetch(server.url, { headers: { authorization: 'Bearer secret', cookie: 'secret=1' } })).text();
    }
    const requests = crlRequests.filter(x => x.url === '/ocsp-good');
    assert.equal(requests.length, 2);
    for (const request of requests) {
        assert.equal(request.method, 'POST');
        assert.equal(request.headers['content-type'], 'application/ocsp-request');
        assert.equal(request.headers.authorization, undefined);
        assert.equal(request.headers.cookie, undefined);
    }
});

test('OCSP revoked and unknown statuses reject before application HTTP data is sent', async function(t) {
    for (const status of [ 'revoked', 'unknown' ]) {
        routes.set('/ocsp-' + status, ocspRoute(ca, { status }));
        const server = await endpoint(t, { ocspUrls: [ crlBase + '/ocsp-' + status ] });
        await assert.rejects(trFetch(server.url, { method: 'POST', body: 'secret' }), function(error) {
            assert.ok(error instanceof trFetch.TrFetchOcspError);
            assert.equal(error.code, 'TR_FETCH_OCSP_CERTIFICATE_REJECTED');
            assert.equal(error.ocspStatus, status);
            assert.match(error.message, new RegExp('responder reports ' + status));
            return true;
        });
        assert.equal(server.hits(), 0);
    }
});

test('OCSP missing, unreachable and invalid responses have distinct policy outcomes', async function(t) {
    const server = await endpoint(t);
    await assert.rejects(trFetch(server.url, { trFetchOcspPolicy: { missingOcspUri: 'reject' } }), { code: 'TR_FETCH_OCSP_MISSING_URI' });
    for (const uri of [ 'file:///tmp/ocsp', 'ldap://localhost/cn=ca', crlBase + '/no-ocsp' ]) {
        await assert.rejects(trFetch(server.url, { trFetchOcspUriOverride: uri }), { code: 'TR_FETCH_OCSP_UNREACHABLE_URI' });
    }
    routes.set('/ocsp-invalid', Buffer.from('garbage'));
    await assert.rejects(trFetch(server.url, { trFetchOcspUriOverride: crlBase + '/ocsp-invalid' }), {
        code: 'TR_FETCH_OCSP_CERTIFICATE_REJECTED', ocspStatus: 'invalid-response'
    });
    assert.equal(server.hits(), 0);
    const warnings = [];
    t.mock.method(process, 'emitWarning', warning => warnings.push(warning));
    await (await trFetch(server.url, { trFetchOcspPolicy: { missingOcspUri: 'warn' } })).text();
    await (await trFetch(server.url, { trFetchOcspUriOverride: crlBase + '/ocsp-invalid',
                                       trFetchOcspPolicy: { rejectedCertificate: 'warn' } })).text();
    assert.deepEqual(warnings.map(x => [ x.name, x.code ]), [
        [ 'TrFetchOcspWarning', 'TR_FETCH_OCSP_MISSING_URI' ],
        [ 'TrFetchOcspWarning', 'TR_FETCH_OCSP_CERTIFICATE_REJECTED' ]
    ]);
    await (await trFetch(server.url, { trFetchOcspUriOverride: crlBase + '/ocsp-invalid',
                                       trFetchOcspPolicy: { rejectedCertificate: 'ignore' } })).text();
    assert.equal(warnings.length, 2);
});

test('OCSP override replaces the leaf URI; redirects and alternate URIs remain checked', async function(t) {
    routes.set('/ocsp-override', ocspRoute(ca));
    const server = await endpoint(t, { ocspUrls: [ 'file:///tmp/ocsp' ] });
    await (await trFetch(server.url, { trFetchOcspUriOverride: new URL(crlBase + '/ocsp-override') })).text();
    routes.set('/ocsp-redirect', (req, res) => res.writeHead(307, { location: '/ocsp-override' }).end());
    await (await trFetch(server.url, { trFetchOcspUriOverride: crlBase + '/ocsp-redirect' })).text();
    routes.set('/ocsp-local-redirect', (req, res) => res.writeHead(307, { location: 'file:///tmp/ocsp' }).end());
    await assert.rejects(trFetch(server.url, { trFetchOcspUriOverride: crlBase + '/ocsp-local-redirect' }), { code: 'TR_FETCH_OCSP_UNREACHABLE_URI' });
    const fallback = await endpoint(t, { ocspUrls: [ crlBase + '/no-ocsp', crlBase + '/ocsp-override' ] });
    await (await trFetch(fallback.url)).text();
});

test('disabled flags skip only their own checks and both disabled cause no revocation lookups', async function(t) {
    routes.set('/ocsp-disabled', ocspRoute(ca, { status: 'revoked' }));
    const server = await endpoint(t, { urls: [ crlBase + '/revoked' ], ocspUrls: [ crlBase + '/ocsp-disabled' ] });
    const before = crlRequests.length;
    await (await trFetch(server.url, {
        trFetchCrlPolicy: { disabled: true }, trFetchOcspPolicy: { disabled: true }
    })).text();
    assert.equal(crlRequests.length, before);
    await assert.rejects(trFetch(server.url, {
        trFetchCrlPolicy: { disabled: true }
    }), { code: 'TR_FETCH_OCSP_CERTIFICATE_REJECTED' });
    await assert.rejects(trFetch(server.url, {
        trFetchOcspPolicy: { disabled: true }
    }), { code: 'TR_FETCH_CERTIFICATE_REVOKED' });
    await (await trFetch(server.url, {
        trFetchCrlPolicy: { disabled: true }, trFetchCrlOverride: 'malformed CRL',
        trFetchOcspPolicy: { disabled: true }, trFetchOcspUriOverride: 'file:///tmp/ocsp'
    })).text();
});

test('false, null and undefined disabled values keep each check enabled', async function(t) {
    const server = await endpoint(t);
    for (const disabled of [ false, null, undefined ]) {
        await assert.rejects(trFetch(server.url, {
            trFetchCrlPolicy: { disabled }, trFetchCrlOverride: 'bad', trFetchOcspPolicy: { disabled: true }
        }), { code: 'TR_FETCH_CRL_INVALID' });
        await assert.rejects(trFetch(server.url, {
            trFetchCrlPolicy: { disabled: true }, trFetchOcspPolicy: { disabled, missingOcspUri: 'reject' }
        }), { code: 'TR_FETCH_OCSP_MISSING_URI' });
    }
    assert.equal(server.hits(), 0);
});

test('OCSP depth is independent of CRL depth and overrides apply only to the leaf', async function(t) {
    const intermediate = await fixtures.certificate({ issuer: ca, ca: true, serial: 100,
                                                      ocspUrls: [ crlBase + '/ocsp-intermediate' ] });
    routes.set('/ocsp-intermediate', ocspRoute(ca, { status: 'revoked' }));
    routes.set('/ocsp-leaf', ocspRoute(intermediate));
    const server = await endpoint(t, { issuer: intermediate, chain: intermediate.pem });
    for (const depth of [ undefined, 0, 'leaf' ]) {
        await (await trFetch(server.url, {
            trFetchCrlCheckDepth: 'full-chain', trFetchOcspCheckDepth: depth,
            trFetchOcspUriOverride: crlBase + '/ocsp-leaf'
        })).text();
    }
    for (const depth of [ 1, 2, 'full-chain' ]) {
        await assert.rejects(trFetch(server.url, { trFetchCrlCheckDepth: 0,
                                                   trFetchOcspCheckDepth: depth, trFetchOcspUriOverride: crlBase + '/ocsp-leaf'
                                                 }), { code: 'TR_FETCH_OCSP_CERTIFICATE_REJECTED', serialNumber: '64' });
    }
    routes.set('/ocsp-intermediate', ocspRoute(ca));
    await (await trFetch(server.url, { trFetchOcspCheckDepth: 'full-chain',
                                       trFetchOcspUriOverride: crlBase + '/ocsp-leaf', trFetchOcspPolicy: { missingOcspUri: 'reject' }
                                     })).text();
});

test('OCSP follows application redirects and respects cancellation during responder lookup', async function(t) {
    routes.set('/ocsp-redirect-revoked', ocspRoute(ca, { status: 'revoked' }));
    const revoked = await endpoint(t, { ocspUrls: [ crlBase + '/ocsp-redirect-revoked' ] });
    const redirect = await endpoint(t, {}, (req, res) => res.writeHead(302, { location: revoked.url }).end());
    await assert.rejects(trFetch(redirect.url), { code: 'TR_FETCH_OCSP_CERTIFICATE_REJECTED' });
    assert.equal(revoked.hits(), 0);
    let started;
    const downloading = new Promise(resolve => { started = resolve; });
    routes.set('/ocsp-hang', () => { started(); });
    const server = await endpoint(t, { ocspUrls: [ crlBase + '/ocsp-hang' ] });
    const controller = new AbortController();
    const pending = trFetch(server.url, { signal: controller.signal });
    const rejected = assert.rejects(pending, error => error === controller.signal.reason);
    await downloading;
    controller.abort(new Error('cancel OCSP'));
    await rejected;
    assert.equal(server.hits(), 0);
});

test('disabling both revocation checks never disables TLS trust or hostname verification', async function(t) {
    const unknownCA = await fixtures.certificate({ ca: true, serial: 200 });
    const untrusted = await endpoint(t, { issuer: unknownCA });
    const trusted = await endpoint(t);
    const options = { trFetchCrlPolicy: { disabled: true }, trFetchOcspPolicy: { disabled: true } };
    await assert.rejects(trFetch(untrusted.url, options), error => (error instanceof TypeError) && !! error.cause);
    await assert.rejects(trFetch(trusted.url.replace('localhost', '127.0.0.1'), options), error => (error instanceof TypeError) && !! error.cause);
    assert.equal(untrusted.hits(), 0);
    assert.equal(trusted.hits(), 0);
});
