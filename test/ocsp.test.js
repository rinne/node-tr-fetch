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

test('thisUpdate and producedAt may be in the future only within the thisUpdate clock skew', async function() {
    const now = Date.now();
    const ahead = seconds => ({ start: now + (seconds * 1000), producedAt: now + (seconds * 1000), end: now + 3600000 });
    async function check(options, clockSkew) {
        const response = await fixtures.ocsp(ca, request.bytes, options);
        return validateOcspResponse(response.der, request, leaf.cert, ca.cert, now, undefined, clockSkew);
    }
    // Without an allowance, both must not be in the future.
    await assert.rejects(check(ahead(1)), /producedAt is invalid or in the future/);
    await assert.rejects(check(ahead(1), { thisUpdate: 0 }), /producedAt is invalid or in the future/);
    await assert.rejects(check({ start: now + 1000, producedAt: now - 1000 }, { thisUpdate: 900 }), /future validity/);
    assert.equal((await check(ahead(0), { thisUpdate: 0 })).status, 'good');
    // Up to and including the allowance; one second over fails.
    for (const seconds of [ 1, 600, 899, 900 ]) {
        assert.equal((await check(ahead(seconds), { thisUpdate: 900 })).status, 'good', String(seconds));
    }
    await assert.rejects(check(ahead(901), { thisUpdate: 900 }), /producedAt is invalid or in the future/);
    await assert.rejects(check({ ...ahead(901), producedAt: now }, { thisUpdate: 900 }), /future validity/);
    // Within the largest allowance (the signer must still be valid at producedAt).
    assert.equal((await check({ ...ahead(86000), end: now + 90000000 }, { thisUpdate: 86400 })).status, 'good');
    // producedAt alone ahead, with thisUpdate in the past.
    assert.equal((await check({ producedAt: now + 60000 }, { thisUpdate: 60 })).status, 'good');
    await assert.rejects(check({ producedAt: now + 61000 }, { thisUpdate: 60 }), /producedAt/);
    // The allowance never relaxes the ordering or nextUpdate checks.
    await assert.rejects(check({ start: now + 60000, producedAt: now + 30000 }, { thisUpdate: 900 }), /future validity/);
    await assert.rejects(check({ ...ahead(60), end: now + 60000 }, { thisUpdate: 900 }), /future validity/);
    await assert.rejects(check({ ...ahead(60), end: now - 1 }, { thisUpdate: 900 }), /future validity/);
    // Revocation times may be up to producedAt, also in the future.
    assert.equal((await check({ ...ahead(300), status: 'revoked' }, { thisUpdate: 900 })).status, 'revoked');
    // The result keeps producedAt for cache checks.
    assert.equal((await check(ahead(300), { thisUpdate: 900 })).producedAt, now + 300000);
});

test('nextUpdate is strict unless the nextUpdate clock skew accepts a recently expired response', async function() {
    const now = Date.now();
    const expired = seconds => ({ start: now - 3600000, producedAt: now - 3600000, end: now - (seconds * 1000) });
    async function check(options, clockSkew, signer) {
        const response = await fixtures.ocsp(ca, request.bytes, { ...options, ...(signer ? { signer, byKey: true } : {}) });
        return validateOcspResponse(response.der, request, leaf.cert, ca.cert, now, undefined, clockSkew);
    }
    await assert.rejects(check(expired(0)), /expired or is stale/);
    await assert.rejects(check(expired(0), { thisUpdate: 900, nextUpdate: 0 }), /expired or is stale/);
    await assert.rejects(check(expired(1), { thisUpdate: 86400 }), /expired or is stale/);
    for (const seconds of [ 0, 1, 59 ]) {
        const result = await check(expired(seconds), { nextUpdate: 60 });
        assert.equal(result.status, 'good');
        // nextUpdate is the response's own; usableUntil adds the allowance.
        assert.equal(result.nextUpdate, now - (seconds * 1000));
        assert.equal(result.usableUntil, now - (seconds * 1000) + 60000);
    }
    await assert.rejects(check(expired(60), { nextUpdate: 60 }), /expired or is stale/);
    // A response without nextUpdate is valid for five minutes, plus the allowance.
    const missing = { start: now - 330000, producedAt: now - 330000, end: null };
    await assert.rejects(check(missing), /expired or is stale/);
    assert.equal((await check(missing, { nextUpdate: 60 })).usableUntil, now - 330000 + 300000 + 60000);
    // A strict check has usableUntil equal to nextUpdate.
    const strict = await check({ producedAt: now, end: now + 3600000 });
    assert.equal(strict.usableUntil, strict.nextUpdate);
    // The allowance never outlives the signer certificate.
    const eku = fixtures.extension('2.5.29.37', new pki.ExtKeyUsage({ keyPurposes: [ '1.3.6.1.5.5.7.3.9' ] }).toSchema());
    const noCheck = fixtures.extension('1.3.6.1.5.5.7.48.1.5', new asn1.Null());
    const signer = await fixtures.certificate({ issuer: ca, serial: 102, extraExtensions: [ eku, noCheck ] });
    const bounded = await check({ producedAt: now, end: now + 3600000 }, { nextUpdate: 86400 }, signer);
    // Certificate times have whole seconds.
    assert.equal(bounded.usableUntil, Math.floor(signer.cert.notAfter.value.getTime() / 1000) * 1000);
    assert.equal(bounded.nextUpdate, now + 3600000);
});
