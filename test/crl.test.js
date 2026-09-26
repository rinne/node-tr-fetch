'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const asn1 = require('asn1js');
const pki = require('pkijs');
const { parseCrl, validateCrl, authenticateCrl, checkRevocationList } = require('../crl');
const fixtures = require('./fixtures');

let ca, leaf;
test.before(async function() {
    ca = await fixtures.certificate({ ca: true });
    leaf = await fixtures.certificate({ issuer: ca, serial: 42 });
});

async function validate(options = {}, urls = []) {
    const data = await fixtures.crl(ca, options);
    return validateCrl(parseCrl(data.der), leaf.cert, ca.cert, urls);
}

test('valid signed CRL distinguishes listed and unlisted certificate serials', async function() {
    assert.equal((await validate({ serials: [ 1, 2 ] })).revoked, false);
    assert.equal((await validate({ serials: [ 1, 42, 99 ] })).revoked, true);
});

test('delta CRLs and unknown critical extensions cannot report a certificate as good', async function() {
    await assert.rejects(validate({ extensions: [ fixtures.extension('2.5.29.27', new asn1.Integer({ value: 1 }), true) ] }), /Delta CRLs/);
    await assert.rejects(validate({ extensions: [ fixtures.extension('1.2.3.4.5', new asn1.Null(), true) ] }), /Unsupported critical CRL extension/);
});

test('reject indirect, reason-limited, attribute and wrong-certificate-type CRL scopes', async function() {
    for (const idp of [ { indirectCRL: true }, { onlySomeReasons: 0x40 }, { onlyContainsAttributeCerts: true }, { onlyContainsCACerts: true } ]) {
        const extension = fixtures.extension('2.5.29.28', new pki.IssuingDistributionPoint(idp).toSchema(), true);
        await assert.rejects(validate({ extensions: [ extension ] }), /unsupported|scope does not cover/);
    }
});

test('named CRL scope must match the effective distribution point', async function() {
    const url = 'http://ca.example.com/one.crl';
    const extension = fixtures.extension('2.5.29.28', new pki.IssuingDistributionPoint({
        distributionPoint: [ new pki.GeneralName({ type: 6, value: url }) ], onlyContainsUserCerts: true
    }).toSchema(), true);
    assert.equal((await validate({ extensions: [ extension ] }, [ url ])).revoked, false);
    await assert.rejects(validate({ extensions: [ extension ] }, [ 'http://ca.example.com/two.crl' ]), /does not match/);
    await assert.rejects(validate({ extensions: [ extension ] }), /does not match/);
});

test('CRL signer must have cRLSign permission when keyUsage is present', async function() {
    const issuer = await fixtures.certificate({ ca: true, serial: 9, crlSign: false });
    const certificate = await fixtures.certificate({ issuer });
    const data = await fixtures.crl(issuer);
    await assert.rejects(validateCrl(parseCrl(data.der), certificate.cert, issuer.cert, []), /does not permit CRL signing/);
});

test('a same-name replacement CA cannot authenticate a CRL for the real certificate', async function() {
    const impostor = await fixtures.certificate({ ca: true });
    const data = await fixtures.crl(impostor);
    await assert.rejects(validateCrl(parseCrl(data.der), leaf.cert, impostor.cert, []), /did not issue/);
});

test('duplicate extensions, inconsistent algorithms, weak signatures and trailing bytes fail', async function() {
    const number = fixtures.extension('2.5.29.20', new asn1.Integer({ value: 1 }));
    await assert.rejects(validate({ extensions: [ number, number ] }), /Duplicate extension/);
    await assert.rejects(validate({ hash: 'SHA-1' }), /weak CRL signature algorithm/);
    const data = await fixtures.crl(ca);
    const crl = parseCrl(data.der);
    crl.crl.signatureAlgorithm = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.10045.4.3.3' });
    await assert.rejects(validateCrl(crl, leaf.cert, ca.cert, []), /identifiers disagree/);
    assert.throws(() => parseCrl(Buffer.concat([ data.der, Buffer.from([ 0 ]) ])), /trailing bytes/);
    assert.throws(() => parseCrl(Buffer.from(data.pem + data.pem)), /Malformed PEM/);
});

test('indirect entries, removeFromCRL and unknown critical entry extensions are rejected', async function() {
    for (const extension of [
        fixtures.extension('2.5.29.29', new pki.GeneralNames({ names: [ new pki.GeneralName({ type: 4, value: ca.cert.subject }) ] }).toSchema(), true),
        fixtures.extension('2.5.29.21', new asn1.Enumerated({ value: 8 })),
        fixtures.extension('1.2.3.4.5', new asn1.Null(), true)
    ]) {
        const entry = new pki.RevokedCertificate({ userCertificate: new asn1.Integer({ value: 1 }),
                                                   revocationDate: new pki.Time({ value: new Date(Date.now() - 60000) }),
                                                   crlEntryExtensions: new pki.Extensions({ extensions: [ extension ] }) });
        await assert.rejects(validate({ entries: [ entry ] }), /unsupported|Invalid revocation reason|Unsupported critical/);
    }
});

test('large CRLs beyond the default ASN.1 node limit are parsed', async function() {
    // About 5000 entries is typical of a public CA CRL shard; asn1js's default
    // limit of 10000 nodes would reject it.
    const serials = Array.from({ length: 5000 }, (_, i) => 1000 + i);
    assert.equal((await validate({ serials })).revoked, false);
    assert.equal((await validate({ serials: [ ...serials, 42 ] })).revoked, true);
});

test('CRLs with hundreds of thousands of entries are scanned without decoding every entry', async function() {
    // About 1.6 million ASN.1 nodes: far beyond what an object tree can hold
    // in reasonable memory. Serial 42 is listed last.
    const bytes = await fixtures.bulkCrl(ca, 400000, { serials: [ 42 ] });
    const crl = parseCrl(bytes);
    assert.equal(crl.revokedCount, 400001);
    assert.equal((await validateCrl(crl, leaf.cert, ca.cert, [])).revoked, true);
    const other = await fixtures.certificate({ issuer: ca, serial: 43 });
    assert.equal((await validateCrl(crl, other.cert, ca.cert, [])).revoked, false);
    const tampered = Buffer.from(bytes);
    tampered[tampered.length - 200] ^= 1;
    await assert.rejects(validateCrl(parseCrl(tampered), leaf.cert, ca.cert, []), /signature verification failed/);
});

test('scanned entries are authenticated before their problems are reported, and malformed ones fail', async function() {
    const reason = code => Buffer.from([ 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, code ]);
    const entry = extensions => Buffer.from([ 0x30, 0x14 + extensions.length, 0x02, 0x01, 0x07, 0x17, 0x0d,
        ...Buffer.from('260101000000Z'), 0x30, extensions.length, ...extensions ]);
    const good = await fixtures.bulkCrl(ca, 10, { entry: entry(reason(1)) });
    assert.equal((await validateCrl(parseCrl(good), leaf.cert, ca.cert, [])).revoked, false);
    const removeFromCrl = await fixtures.bulkCrl(ca, 10, { entry: entry(reason(8)) });
    await assert.rejects(validateCrl(parseCrl(removeFromCrl), leaf.cert, ca.cert, []), /Invalid revocation reason/);
    const impostor = await fixtures.certificate({ ca: true, serial: 9 });
    await assert.rejects(validateCrl(parseCrl(await fixtures.bulkCrl(impostor, 10, { entry: entry(reason(8)) })), leaf.cert, ca.cert, []),
        /issuer/);
    const duplicate = await fixtures.bulkCrl(ca, 10, { entry: entry(Buffer.concat([ reason(1), reason(1) ])) });
    await assert.rejects(validateCrl(parseCrl(duplicate), leaf.cert, ca.cert, []), /Duplicate extension 2\.5\.29\.21/);
    for (const [bad, message] of [
        [ [ 0x30, 0x03, 0x02, 0x01, 0x07 ], /truncated element/ ],
        [ [ 0x30, 0x07, 0x04, 0x01, 0x07, 0x17, 0x02, 0x30, 0x30 ], /Malformed revoked certificate entry/ ],
        [ [ 0x30, 0x05, 0x02, 0x01, 0x07, 0x17, 0x7f ], /exceeds its container/ ],
        [ [ 0x30, 0x09, 0x02, 0x01, 0x07, 0x17, 0x02, 0x30, 0x30, 0x30, 0x05 ], /exceeds its container/ ]
    ]) {
        const bytes = await fixtures.bulkCrl(ca, 10, { entry: Buffer.from(bad) });
        assert.throws(() => parseCrl(bytes), message);
    }
});

function revokedEntry(serial) {
    const number = Buffer.concat([ Buffer.from([ 0x02, serial.length ]), serial ]);
    const date = Buffer.concat([ Buffer.from([ 0x17, 0x0d ]), Buffer.from('260101000000Z') ]);
    return Buffer.concat([ Buffer.from([ 0x30, number.length + date.length ]), number, date ]);
}

test('an authenticated revocation list serves every certificate of its issuer by exact serial bytes', async function() {
    // Serial 200 is encoded as 00 C8; a CRL listing only C8 (a negative
    // serial) must not revoke it, while one listing 00 C8 must.
    const certificates = {};
    for (const serial of [ 42, 43, 200, 0x100005, 0x100006 ]) {
        certificates[serial] = (await fixtures.certificate({ issuer: ca, serial })).cert;
    }
    const lists = {
        c8: await authenticateCrl(parseCrl(await fixtures.bulkCrl(ca, 6, { serials: [ 42, 200 ] })), ca.cert),
        '00c8': await authenticateCrl(parseCrl(await fixtures.bulkCrl(ca, 0, { entry: revokedEntry(Buffer.from([ 0, 200 ])) })), ca.cert)
    };
    const check = (list, serial) => checkRevocationList(list, certificates[serial], ca.cert, []).then(x => x.revoked);
    assert.equal(await check(lists.c8, 42), true);
    assert.equal(await check(lists.c8, 43), false);
    assert.equal(await check(lists.c8, 200), false);
    assert.equal(await check(lists.c8, 0x100005), true);
    assert.equal(await check(lists.c8, 0x100006), false);
    assert.equal(await check(lists['00c8'], 200), true);
    assert.equal(await check(lists['00c8'], 42), false);
    assert.equal(lists.c8.revokedCount, 8);
    assert.equal(lists.c8.serials.count, 8);
    assert.equal(lists.c8.serials.bytes, (6 * 3) + 2);
});

test('a revocation list keeps no reference to the CRL bytes and cannot be altered', async function() {
    const bytes = await fixtures.bulkCrl(ca, 1000, { serials: [ 42 ] });
    const list = await authenticateCrl(parseCrl(bytes), ca.cert);
    bytes.fill(0);
    const other = await fixtures.certificate({ issuer: ca, serial: 43 });
    assert.equal((await checkRevocationList(list, leaf.cert, ca.cert, [])).revoked, true);
    assert.equal((await checkRevocationList(list, other.cert, ca.cert, [])).revoked, false);
    assert.equal(list.serials.bytes, (1000 * 3) + 1);
    assert.equal(list.size, bytes.length);
    for (const value of Object.values(list)) {
        assert.ok(! (value instanceof Uint8Array), 'no CRL bytes are kept');
    }
    assert.ok(Object.isFrozen(list) && Object.isFrozen(list.scope));
    assert.throws(() => {
        list.scope = {};
    }, TypeError);
    assert.throws(() => {
        list.scope.onlyUserCertificates = false;
    }, TypeError);
});

test('dates, scope, issuer and issuance are checked on every use of a revocation list', async function() {
    const url = 'http://ca.example.com/one.crl';
    const idp = fixtures.extension('2.5.29.28', new pki.IssuingDistributionPoint({
        distributionPoint: [ new pki.GeneralName({ type: 6, value: url }) ], onlyContainsUserCerts: true
    }).toSchema(), true);
    const start = Date.now() - 60000;
    const end = Date.now() + 3600000;
    const list = await authenticateCrl(parseCrl((await fixtures.crl(ca, { serials: [ 42 ], extensions: [ idp ], start, end })).der), ca.cert);
    assert.equal((await checkRevocationList(list, leaf.cert, ca.cert, [ url ])).revoked, true);
    assert.equal((await checkRevocationList(list, leaf.cert, ca.cert, [ url ])).nextUpdate, list.nextUpdate);
    await assert.rejects(checkRevocationList(list, leaf.cert, ca.cert, [ url ], list.thisUpdate - 1), /not yet valid/);
    await assert.rejects(checkRevocationList(list, leaf.cert, ca.cert, [ url ], list.nextUpdate), /expired/);
    await assert.rejects(checkRevocationList(list, leaf.cert, ca.cert, [ 'http://ca.example.com/two.crl' ]), /does not match/);
    const intermediate = await fixtures.certificate({ issuer: ca, ca: true, serial: 77 });
    await assert.rejects(checkRevocationList(list, intermediate.cert, ca.cert, [ url ]), /scope does not cover/);
    const stranger = await fixtures.certificate({ issuer: await fixtures.certificate({ ca: true, serial: 9 }), serial: 42 });
    await assert.rejects(checkRevocationList(list, stranger.cert, ca.cert, [ url ]), /issuer does not match/);
    const impostor = await fixtures.certificate({ ca: true });
    const forged = await fixtures.certificate({ issuer: impostor, serial: 44 });
    await assert.rejects(checkRevocationList(list, forged.cert, ca.cert, [ url ]), /did not issue/);
    await assert.rejects(checkRevocationList(list, leaf.cert, impostor.cert, [ url ]), /different issuer certificate/);
    // The CRL-only scope for CA certificates, checked the other way round.
    const caOnly = fixtures.extension('2.5.29.28', new pki.IssuingDistributionPoint({ onlyContainsCACerts: true }).toSchema(), true);
    const caList = await authenticateCrl(parseCrl((await fixtures.crl(ca, { extensions: [ caOnly ] })).der), ca.cert);
    assert.equal((await checkRevocationList(caList, intermediate.cert, ca.cert, [])).revoked, false);
    await assert.rejects(checkRevocationList(caList, leaf.cert, ca.cert, []), /scope does not cover/);
});

test('a revocation list is built only after the CRL authenticates', async function() {
    const bytes = await fixtures.bulkCrl(ca, 10);
    const other = await fixtures.certificate({ ca: true, serial: 9 });
    await assert.rejects(authenticateCrl(parseCrl(bytes), other.cert), /issuer does not match/);
    const tampered = Buffer.from(bytes);
    tampered[tampered.length - 100] ^= 1;
    await assert.rejects(authenticateCrl(parseCrl(tampered), ca.cert), /signature verification failed/);
    const serialsModule = require('../serials');
    const original = serialsModule.buildSerialIndex;
    let builds = 0;
    serialsModule.buildSerialIndex = function(...args) {
        builds++;
        return original(...args);
    };
    try {
        delete require.cache[require.resolve('../crl')];
        const fresh = require('../crl');
        await assert.rejects(fresh.authenticateCrl(fresh.parseCrl(tampered), ca.cert), /signature verification failed/);
        assert.equal(builds, 0);
        await fresh.authenticateCrl(fresh.parseCrl(bytes), ca.cert);
        assert.equal(builds, 1);
    } finally {
        serialsModule.buildSerialIndex = original;
        delete require.cache[require.resolve('../crl')];
    }
});

test('CRL signatures verify for the supported RSA, RSA-PSS and ECDSA algorithms, and tampering fails', async function() {
    const rsa = name => ({ name, modulusLength: 2048, publicExponent: new Uint8Array([ 1, 0, 1 ]) });
    for (const [keyAlgorithm, hash, algorithmId] of [
        [ { name: 'ECDSA', namedCurve: 'P-256' }, 'SHA-256', '1.2.840.10045.4.3.2' ],
        [ { name: 'ECDSA', namedCurve: 'P-384' }, 'SHA-384', '1.2.840.10045.4.3.3' ],
        [ { name: 'ECDSA', namedCurve: 'P-521' }, 'SHA-512', '1.2.840.10045.4.3.4' ],
        [ { ...rsa('RSASSA-PKCS1-v1_5'), hash: 'SHA-256' }, 'SHA-256', '1.2.840.113549.1.1.11' ],
        [ { ...rsa('RSASSA-PKCS1-v1_5'), hash: 'SHA-384' }, 'SHA-384', '1.2.840.113549.1.1.12' ],
        [ { ...rsa('RSASSA-PKCS1-v1_5'), hash: 'SHA-512' }, 'SHA-512', '1.2.840.113549.1.1.13' ],
        [ { ...rsa('RSA-PSS'), hash: 'SHA-256' }, 'SHA-256', '1.2.840.113549.1.1.10' ],
        [ { ...rsa('RSA-PSS'), hash: 'SHA-384' }, 'SHA-384', '1.2.840.113549.1.1.10' ]
    ]) {
        const label = `${keyAlgorithm.name} ${keyAlgorithm.namedCurve ?? ''} ${hash}`;
        const issuer = await fixtures.certificate({ ca: true, keyAlgorithm, hash });
        const certificate = await fixtures.certificate({ issuer, serial: 42, hash });
        const good = await fixtures.crl(issuer, { hash });
        assert.equal(good.value.signatureAlgorithm.algorithmId, algorithmId, label);
        assert.equal((await validateCrl(parseCrl(good.der), certificate.cert, issuer.cert, [])).revoked, false, label);
        const listed = await fixtures.crl(issuer, { hash, serials: [ 42 ] });
        assert.equal((await validateCrl(parseCrl(listed.der), certificate.cert, issuer.cert, [])).revoked, true, label);
        for (const offset of [ 30, good.der.length - 10 ]) {
            const tampered = Buffer.from(good.der);
            tampered[offset] ^= 0x01;
            await assert.rejects(validateCrl(parseCrl(tampered), certificate.cert, issuer.cert, []),
                /signature verification failed|disagree|Malformed|issuer/, `${label} at ${offset}`);
        }
    }
});

test('CRL signature algorithm, key type and parameters must agree', async function() {
    const data = await fixtures.crl(ca);
    // An RSA algorithm claimed for an ECDSA issuer key.
    const mismatched = parseCrl(data.der);
    const rsaSha256 = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.11', algorithmParams: new asn1.Null() });
    mismatched.crl.signatureAlgorithm = rsaSha256;
    mismatched.crl.signature = rsaSha256;
    await assert.rejects(validateCrl(mismatched, leaf.cert, ca.cert, []), /signature verification failed/);
    // RSA-PSS with MGF1 over a different hash than the signature.
    const rsaIssuer = await fixtures.certificate({ ca: true, keyAlgorithm: { name: 'RSA-PSS', modulusLength: 2048,
        publicExponent: new Uint8Array([ 1, 0, 1 ]), hash: 'SHA-256' } });
    const rsaLeaf = await fixtures.certificate({ issuer: rsaIssuer, serial: 42 });
    const pss = parseCrl((await fixtures.crl(rsaIssuer)).der);
    const sha256 = new pki.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.1', algorithmParams: new asn1.Null() });
    const sha1 = new pki.AlgorithmIdentifier({ algorithmId: '1.3.14.3.2.26', algorithmParams: new asn1.Null() });
    const params = new pki.RSASSAPSSParams({ hashAlgorithm: sha256, saltLength: 32,
        maskGenAlgorithm: new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.8', algorithmParams: sha1.toSchema() }) });
    const odd = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.10', algorithmParams: params.toSchema() });
    pss.crl.signatureAlgorithm = odd;
    pss.crl.signature = odd;
    await assert.rejects(validateCrl(pss, rsaLeaf.cert, rsaIssuer.cert, []), /Unsupported RSA-PSS parameters/);
    // A signature BIT STRING with unused bits.
    const padded = parseCrl(data.der);
    padded.crl.signatureValue = new asn1.BitString({ valueHex: padded.crl.signatureValue.valueBlock.valueHexView, unusedBits: 1 });
    await assert.rejects(validateCrl(padded, leaf.cert, ca.cert, []), /signature verification failed/);
});

test('entry extensions are checked per entry across many entries', async function() {
    const reason = code => Buffer.from([ 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, code ]);
    const entry = (serial, extensions) => {
        const number = Buffer.from([ 0x02, 0x02, serial >> 8, serial & 0xff ]);
        const date = Buffer.concat([ Buffer.from([ 0x17, 0x0d ]), Buffer.from('260101000000Z') ]);
        const list = Buffer.concat([ Buffer.from([ 0x30, extensions.length ]), extensions ]);
        return Buffer.concat([ Buffer.from([ 0x30, number.length + date.length + list.length ]), number, date, list ]);
    };
    // Every entry has a reason code; one per entry is not a duplicate.
    const entries = Array.from({ length: 2000 }, (_, i) => entry(0x1000 + i, reason(1 + (i % 6))));
    const many = await fixtures.bulkCrl(ca, 0, { entry: Buffer.concat(entries) });
    const list = await authenticateCrl(parseCrl(many), ca.cert);
    assert.equal(list.serials.count, 2000);
    const late = await fixtures.bulkCrl(ca, 0, { entry: Buffer.concat([ ...entries, entry(0x7000, Buffer.concat([ reason(1), reason(1) ])) ]) });
    await assert.rejects(authenticateCrl(parseCrl(late), ca.cert), /Duplicate extension 2\.5\.29\.21/);
    const removed = await fixtures.bulkCrl(ca, 0, { entry: Buffer.concat([ ...entries, entry(0x7001, reason(8)) ]) });
    await assert.rejects(authenticateCrl(parseCrl(removed), ca.cert), /Invalid revocation reason/);
    const critical = Buffer.from([ 0x30, 0x0d, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x01, 0x01, 0xff, 0x04, 0x03, 0x0a, 0x01, 0x01 ]);
    const flagged = await fixtures.bulkCrl(ca, 0, { entry: Buffer.concat([ ...entries, entry(0x7002, critical) ]) });
    await assert.rejects(authenticateCrl(parseCrl(flagged), ca.cert), /Unsupported critical CRL entry extension 2\.5\.29\.21/);
    const issuerExtension = Buffer.from([ 0x30, 0x07, 0x06, 0x03, 0x55, 0x1d, 0x1d, 0x04, 0x00 ]);
    const indirect = await fixtures.bulkCrl(ca, 0, { entry: Buffer.concat([ ...entries, entry(0x7003, issuerExtension) ]) });
    await assert.rejects(authenticateCrl(parseCrl(indirect), ca.cert), /certificateIssuer entries are unsupported/);
});
