'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const asn1 = require('asn1js');
const pki = require('pkijs');
const { parseCrl, validateCrl } = require('../crl');
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
    crl.signatureAlgorithm = new pki.AlgorithmIdentifier({ algorithmId: '1.2.840.10045.4.3.3' });
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
