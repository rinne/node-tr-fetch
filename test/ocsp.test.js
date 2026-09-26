'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const asn1 = require('asn1js');
const pki = require('pkijs');
const fixtures = require('./fixtures');
const { createOcspRequest, validateOcspResponse } = require('../ocsp');

let ca, leaf, request;
test.before(async function() {
    ca = await fixtures.certificate({ ca: true });
    leaf = await fixtures.certificate({ issuer: ca, serial: 42 });
    request = await createOcspRequest(leaf.cert, ca.cert);
});

async function validate(options) {
    const response = await fixtures.ocsp(ca, request.bytes, options);
    return validateOcspResponse(response.der, request, leaf.cert, ca.cert);
}

test('issuer-signed OCSP responses authenticate good, revoked and unknown statuses', async function() {
    for (const status of [ 'good', 'revoked', 'unknown' ]) {
        assert.equal((await validate({ status })).status, status);
    }
    assert.equal((await validate({ byKey: true, includeSigner: false })).status, 'good');
});

test('OCSP request uses a fresh 32-byte nonce and contains only the certificate identifier', async function() {
    const other = await createOcspRequest(leaf.cert, ca.cert);
    assert.equal(other.nonce.length, 32);
    assert.notDeepEqual(request.nonce, other.nonce);
    const parsed = pki.OCSPRequest.fromBER(request.bytes);
    assert.equal(parsed.tbsRequest.requestList.length, 1);
    assert.ok(parsed.tbsRequest.requestList[0].reqCert.isEqual(request.certID));
    assert.equal(parsed.tbsRequest.requestorName, undefined);
});

test('bad signature, mismatched nonce, wrong certificate and issuer hashes cannot report good', async function() {
    const other = await fixtures.certificate({ ca: true, serial: 9 });
    await assert.rejects(validate({ signingKey: other.keys.privateKey }), /signature verification failed/);
    await assert.rejects(validate({ nonce: Buffer.alloc(32) }), /nonce does not match/);
    for (const field of [ 'serialNumber', 'issuerNameHash', 'issuerKeyHash' ]) {
        const id = pki.CertID.fromBER(request.certID.toSchema().toBER());
        id[field] = (field === 'serialNumber') ? new asn1.Integer({ value: 99 }) : new asn1.OctetString({ valueHex: Buffer.alloc(20) });
        await assert.rejects(validate({ certID: id }), /exactly one matching certificate ID/);
    }
    await assert.rejects(validate({ signer: other }), /not issued directly/);
});

test('expired, stale, future and unsuccessful OCSP responses fail', async function() {
    for (const [options, message] of [
        [ { start: Date.now() - 7200000, end: Date.now() - 3600000 }, /expired|stale/ ],
        [ { start: Date.now() + 60000 }, /future validity/ ],
        [ { producedAt: Date.now() + 60000 }, /producedAt/ ],
        [ { start: Date.now() - 600000, end: null }, /expired|stale/ ],
        [ { responseStatus: 6 }, /unauthorized/ ],
        [ { responseStatus: 3 }, /tryLater/ ],
        [ { hash: 'SHA-1' }, /weak OCSP signature/ ]
    ]) {
        await assert.rejects(validate(options), message);
    }
    assert.equal((await validate({ nonce: null })).status, 'good');
    assert.equal((await validate({ end: null })).status, 'good');
});

test('critical extensions, duplicate identifiers, duplicate extensions and malformed ASN.1 fail', async function() {
    const unknown = fixtures.extension('1.2.3.4.5', new asn1.Null(), true);
    await assert.rejects(validate({ responseExtensions: [ unknown ] }), /Unsupported critical OCSP extension/);
    await assert.rejects(validate({ singleExtensions: [ unknown ] }), /Unsupported critical OCSP extension/);
    await assert.rejects(validate({ responseExtensions: [ unknown, unknown ] }), /Duplicate extension/);
    const response = await fixtures.ocsp(ca, request.bytes);
    await assert.rejects(validate({ extraResponses: [ response.basic.tbsResponseData.responses[0] ] }), /exactly one matching/);
    await assert.rejects(validateOcspResponse(Buffer.from('garbage'), request, leaf.cert, ca.cert), /ASN.1|schema/);
    await assert.rejects(validateOcspResponse(Buffer.concat([ response.der, Buffer.from([ 0 ]) ]), request, leaf.cert, ca.cert), /trailing bytes/);
});

test('delegated responder requires direct issuance, OCSP EKU, current certificate and no-check', async function() {
    const eku = fixtures.extension('2.5.29.37', new pki.ExtKeyUsage({ keyPurposes: [ '1.3.6.1.5.5.7.3.9' ] }).toSchema());
    const noCheck = fixtures.extension('1.3.6.1.5.5.7.48.1.5', new asn1.Null());
    const signer = await fixtures.certificate({ issuer: ca, serial: 100, extraExtensions: [ eku, noCheck ] });
    assert.equal((await validate({ signer, byKey: true })).status, 'good');
    for (const [options, message] of [
        [ { extraExtensions: [ noCheck ] }, /lacks the OCSP signing/ ],
        [ { extraExtensions: [ eku ] }, /nocheck/ ],
        [ { extraExtensions: [ eku, noCheck ], expired: true }, /expired/ ],
        [ { extraExtensions: [ eku, noCheck ], hash: 'SHA-1' }, /weak OCSP delegated signer/ ],
        [ { extraExtensions: [ eku, noCheck ], keyAlgorithm: { name: 'RSASSA-PKCS1-v1_5',
                                                               modulusLength: 1024, publicExponent: new Uint8Array([ 1, 0, 1 ]), hash: 'SHA-256' } }, /at least 2048 bits/ ]
    ]) {
        const invalid = await fixtures.certificate({ issuer: ca, serial: 101, ...options });
        await assert.rejects(validate({ signer: invalid }), message);
    }
});
