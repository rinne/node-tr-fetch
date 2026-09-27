'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const asn1 = require('asn1js');
const pki = require('pkijs');
const { authenticateCrlStream } = require('../crlstream');
const { parseCrl, authenticateCrl } = require('../crl');
const fixtures = require('./fixtures');

let ca, leaf;
test.before(async function() {
    ca = await fixtures.certificate({ ca: true });
    leaf = await fixtures.certificate({ issuer: ca, serial: 42 });
});

async function* chunked(bytes, size) {
    for (let offset = 0; offset < bytes.length; offset += size) {
        yield bytes.subarray(offset, offset + size);
    }
}

function stream(bytes, serials, { issuer = ca, size = 1000, maxBytes = 64 * 1024 * 1024 } = {}) {
    return authenticateCrlStream(chunked(bytes, size), issuer.cert, maxBytes, serials.map(x => Buffer.from(x)));
}

const keys = result => [ ...result.listed ].map(x => Buffer.from(x, 'latin1').toString('hex')).sort();

function revokedEntry(serial, extensions = Buffer.alloc(0)) {
    const { der } = fixtures;
    return der(0x30, der(0x02, serial), der(0x17, Buffer.from('260101000000Z')), extensions.length ? der(0x30, extensions) : Buffer.alloc(0));
}

// A non-critical extension with an unknown identifier and value bytes.
function unknownExtension(length) {
    return fixtures.der(0x30, Buffer.from([ 0x06, 0x03, 0x2a, 0x03, 0x04 ]), fixtures.der(0x04, Buffer.alloc(length)));
}

test('streamed results agree with the indexed check for every chunk size', async function() {
    const bytes = await fixtures.bulkCrl(ca, 3000, { serials: [ 42 ], entry: revokedEntry(Buffer.from([ 0, 0xc8 ])) });
    const list = await authenticateCrl(parseCrl(bytes), ca.cert);
    const probes = [ [ 42 ], [ 0x10, 0x00, 0x05 ], [ 0x10, 0x0b, 0xb7 ], [ 0x10, 0x0b, 0xb8 ], [ 0, 0xc8 ], [ 0xc8 ], [ 43 ], [], [ 0, 42 ] ];
    const expected = probes.filter(x => list.serials.has(Buffer.from(x))).map(x => Buffer.from(x).toString('hex')).sort();
    assert.deepEqual(expected, [ '00c8', '100005', '100bb7', '2a' ]);
    for (const size of [ 1, 2, 3, 7, 64, 1000, 65536, bytes.length ]) {
        const result = await stream(bytes, probes, { size });
        assert.deepEqual(keys(result), expected, `chunk size ${size}`);
        assert.equal(result.revokedCount, 3002, `chunk size ${size}`);
        assert.equal(result.size, bytes.length);
        assert.equal(result.details.nextUpdate, list.nextUpdate);
        assert.equal(result.details.thisUpdate, list.thisUpdate);
    }
    // No serials to look for still authenticates the whole CRL.
    assert.equal((await stream(bytes, [])).listed.size, 0);
});

test('CRLs without entries, and in PEM form, stream correctly', async function() {
    const empty = await fixtures.crl(ca);
    assert.equal((await stream(empty.der, [ [ 42 ] ])).revokedCount, 0);
    const listed = await fixtures.crl(ca, { serials: [ 42, 7 ] });
    for (const size of [ 1, 5, 100000 ]) {
        const result = await authenticateCrlStream(chunked(Buffer.from('\n  ' + listed.pem), size), ca.cert, 1024 * 1024, [ Buffer.from([ 42 ]) ]);
        assert.deepEqual(keys(result), [ '2a' ]);
        assert.equal(result.revokedCount, 2);
    }
    for (const pem of [ listed.pem + 'junk', listed.pem + listed.pem, listed.pem.replace('X509 CRL', 'CERTIFICATE') ]) {
        await assert.rejects(authenticateCrlStream(chunked(Buffer.from(pem), 50), ca.cert, 1024 * 1024, []),
            error => error.invalidCrl && /Malformed PEM|base64/.test(error.message));
    }
});

test('streamed signatures verify for RSA, RSA-PSS and ECDSA, and tampering anywhere fails', async function() {
    const rsa = name => ({ name, modulusLength: 2048, publicExponent: new Uint8Array([ 1, 0, 1 ]) });
    for (const [keyAlgorithm, hash] of [
        [ { name: 'ECDSA', namedCurve: 'P-256' }, 'SHA-256' ],
        [ { name: 'ECDSA', namedCurve: 'P-384' }, 'SHA-384' ],
        [ { name: 'ECDSA', namedCurve: 'P-521' }, 'SHA-512' ],
        [ { ...rsa('RSASSA-PKCS1-v1_5'), hash: 'SHA-256' }, 'SHA-256' ],
        [ { ...rsa('RSASSA-PKCS1-v1_5'), hash: 'SHA-512' }, 'SHA-512' ],
        [ { ...rsa('RSA-PSS'), hash: 'SHA-256' }, 'SHA-256' ],
        [ { ...rsa('RSA-PSS'), hash: 'SHA-384' }, 'SHA-384' ]
    ]) {
        const label = `${keyAlgorithm.name} ${keyAlgorithm.namedCurve ?? ''} ${hash}`;
        const issuer = await fixtures.certificate({ ca: true, keyAlgorithm, hash });
        const data = await fixtures.crl(issuer, { hash, serials: [ 42, 43, 44 ] });
        const result = await authenticateCrlStream(chunked(data.der, 13), issuer.cert, 1024 * 1024, [ Buffer.from([ 43 ]) ]);
        assert.deepEqual(keys(result), [ '2b' ], label);
        for (const offset of [ 40, data.der.length >> 1, data.der.length - 10 ]) {
            const tampered = Buffer.from(data.der);
            tampered[offset] ^= 0x01;
            await assert.rejects(authenticateCrlStream(chunked(tampered, 13), issuer.cert, 1024 * 1024, []),
                error => error.invalidCrl === true, `${label} at ${offset}`);
        }
    }
    await assert.rejects(stream((await fixtures.crl(ca, { hash: 'SHA-1' })).der, []),
        error => error.invalidCrl && /weak CRL signature algorithm/.test(error.message));
});

test('the header after the entries is checked, and nothing is reported before authentication', async function() {
    const delta = fixtures.extension('2.5.29.27', new asn1.Integer({ value: 1 }), true);
    await assert.rejects(stream((await fixtures.crl(ca, { serials: [ 42 ], extensions: [ delta ] })).der, [ [ 42 ] ]), /Delta CRLs/);
    const caOnly = fixtures.extension('2.5.29.28', new pki.IssuingDistributionPoint({ onlyContainsCACerts: true }).toSchema(), true);
    const scoped = await stream((await fixtures.crl(ca, { serials: [ 42 ], extensions: [ caOnly ] })).der, [ [ 42 ] ]);
    assert.equal(scoped.details.scope.onlyCaCertificates, true);
    // A CRL from another CA with an unsupported entry fails on its issuer,
    // not on the entry, and never reports the listed serial.
    const other = await fixtures.certificate({ ca: true, serial: 9 });
    const reason = Buffer.from([ 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, 8 ]);
    const forged = await fixtures.bulkCrl(other, 10, { serials: [ 42 ], entry: revokedEntry(Buffer.from([ 7 ]), reason) });
    await assert.rejects(stream(forged, [ [ 42 ] ]), error => error.invalidCrl && /issuer does not match/.test(error.message));
    const removed = await fixtures.bulkCrl(ca, 10, { serials: [ 42 ], entry: revokedEntry(Buffer.from([ 7 ]), reason) });
    await assert.rejects(stream(removed, [ [ 42 ] ]), /Invalid revocation reason/);
    const keyCompromise = Buffer.from([ 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, 1 ]);
    const duplicate = await fixtures.bulkCrl(ca, 10, { entry: revokedEntry(Buffer.from([ 7 ]), Buffer.concat([ keyCompromise, keyCompromise ])) });
    await assert.rejects(stream(duplicate, []), /Duplicate extension 2\.5\.29\.21/);
});

test('malformed, truncated, oversized and trailing data is rejected as an invalid CRL', async function() {
    const bytes = await fixtures.bulkCrl(ca, 100, { serials: [ 42 ] });
    const cases = [
        [ Buffer.concat([ bytes, Buffer.from([ 0 ]) ]), /trailing bytes/ ],
        [ bytes.subarray(0, bytes.length - 1), /truncated/ ],
        [ bytes.subarray(0, 300), /truncated/ ],
        [ Buffer.from([ 0x31, 0x03, 0x02, 0x01, 0x00 ]), /Malformed CRL structure/ ],
        [ Buffer.from([ 0x30, 0x80, 0x00, 0x00 ]), /unsupported tag or length encoding/ ],
        [ Buffer.from([ 0x30, 0x85, 1, 0, 0, 0, 0 ]), /unsupported tag or length encoding/ ],
        [ await fixtures.bulkCrl(ca, 10, { entry: Buffer.from([ 0x30, 0x03, 0x02, 0x01, 0x07 ]) }), /truncated element/ ],
        [ await fixtures.bulkCrl(ca, 10, { entry: Buffer.from([ 0x30, 0x07, 0x04, 0x01, 0x07, 0x17, 0x02, 0x30, 0x30 ]) }),
            /Malformed revoked certificate entry/ ],
    ];
    for (const [data, message] of cases) {
        for (const size of [ 1, 1000 ]) {
            await assert.rejects(stream(data, [ [ 42 ] ], { size }), error => error.invalidCrl && message.test(error.message),
                `${message} with chunks of ${size}`);
        }
    }
    const oversized = await fixtures.bulkCrl(ca, 10, { entry: revokedEntry(Buffer.from([ 7 ]), unknownExtension(70000)) });
    await assert.rejects(stream(oversized, []), error => error.invalidCrl && /Revoked certificate entry exceeds the size limit/.test(error.message));
    // A large but acceptable entry, with an unknown non-critical extension;
    // the indexed check accepts it too.
    const unusual = await fixtures.bulkCrl(ca, 10, { entry: revokedEntry(Buffer.from([ 7 ]), unknownExtension(60000)) });
    assert.deepEqual(keys(await stream(unusual, [ [ 7 ] ], { size: 1000 })), [ '07' ]);
    assert.equal((await authenticateCrl(parseCrl(unusual), ca.cert)).serials.has(Buffer.from([ 7 ])), true);
    const hugeExtension = fixtures.extension('1.2.3.4', new asn1.OctetString({ valueHex: new Uint8Array(1100000) }));
    await assert.rejects(stream((await fixtures.crl(ca, { extensions: [ hugeExtension ] })).der, []), /exceeds the size limit/);
});

test('reading stops early on invalid content, and transfer failures are not invalid CRLs', async function() {
    let pulled = 0;
    let closed = false;
    async function* endless() {
        try {
            yield Buffer.from([ 0x31, 0x84, 0x7f, 0xff, 0xff, 0xff ]);
            for (;;) {
                pulled++;
                yield Buffer.alloc(65536);
            }
        } finally {
            closed = true;
        }
    }
    await assert.rejects(authenticateCrlStream(endless(), ca.cert, 1024 * 1024 * 1024, []), error => error.invalidCrl === true);
    // At most the chunk read to tell DER from PEM (32 bytes) follows the first.
    assert.ok(pulled <= 1);
    assert.equal(closed, true);
    const bytes = await fixtures.bulkCrl(ca, 1000);
    await assert.rejects(stream(bytes, [], { maxBytes: bytes.length - 1 }),
        error => error.transport && ! error.invalidCrl && /exceeds maxCrlBytes/.test(error.message));
    assert.equal((await stream(bytes, [], { maxBytes: bytes.length })).size, bytes.length);
    async function* broken() {
        yield bytes.subarray(0, 5000);
        throw new Error('connection reset');
    }
    await assert.rejects(authenticateCrlStream(broken(), ca.cert, 1024 * 1024, []),
        error => error.transport && ! error.invalidCrl && /connection reset/.test(error.message));
});

test('a CRL signed by another issuer, or checked against the wrong issuer, fails', async function() {
    const other = await fixtures.certificate({ ca: true, serial: 9 });
    const bytes = await fixtures.bulkCrl(ca, 50, { serials: [ 42 ] });
    await assert.rejects(stream(bytes, [ [ 42 ] ], { issuer: other }), error => error.invalidCrl && /issuer/.test(error.message));
    const impostor = await fixtures.certificate({ ca: true });
    await assert.rejects(stream(bytes, [ [ 42 ] ], { issuer: impostor }), /signature verification failed/);
    void leaf;
});
