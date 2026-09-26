'use strict';

const { webcrypto } = require('node:crypto');
const asn1 = require('asn1js');
const pki = require('pkijs');

const engine = new pki.CryptoEngine({ name: 'fixtures', crypto: webcrypto });

function pem(label, bytes) {
    return `-----BEGIN ${label}-----\n${Buffer.from(bytes).toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
}

function extension(oid, value, critical = false) {
    return new pki.Extension({ extnID: oid, critical, extnValue: value.toBER() });
}

async function certificate({ issuer, serial = 1, ca = false, urls, ocspUrls, hostname = 'localhost', expired = false,
                             crlSign = true, extraExtensions = [], hash = 'SHA-256', keyAlgorithm = { name: 'ECDSA', namedCurve: 'P-256' } } = {}) {
    const keys = await webcrypto.subtle.generateKey(keyAlgorithm, true, [ 'sign', 'verify' ]);
    const subject = new pki.RelativeDistinguishedNames({ typesAndValues: [
        new pki.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1.Utf8String({ value: ca ? `Test CA ${serial}` : hostname }) })
    ] });
    const cert = new pki.Certificate({ version: 2, serialNumber: new asn1.Integer({ value: serial }), subject, issuer: issuer?.cert.subject ?? subject });
    cert.notBefore.value = new Date(Date.now() - 86400000);
    cert.notAfter.value = new Date(Date.now() + (expired ? -3600000 : 86400000));
    await cert.subjectPublicKeyInfo.importKey(keys.publicKey, engine);
    cert.extensions = [
        extension('2.5.29.19', new pki.BasicConstraints({ cA: ca }).toSchema(), true),
        extension('2.5.29.15', new asn1.BitString({ valueHex: new Uint8Array([ ca ? (crlSign ? 0x06 : 0x04) : 0x80 ]).buffer, unusedBits: ca ? (crlSign ? 1 : 2) : 7 }), true)
    ];
    if (! ca) {
        cert.extensions.push(extension('2.5.29.17', new pki.AltName({ altNames: [ new pki.GeneralName({ type: 2, value: hostname }) ] }).toSchema()));
    }
    if (urls !== undefined) {
        cert.extensions.push(extension('2.5.29.31', new pki.CRLDistributionPoints({ distributionPoints: [
            new pki.DistributionPoint({ distributionPoint: urls.map(value => new pki.GeneralName({ type: 6, value })) })
        ] }).toSchema()));
    }
    if (ocspUrls !== undefined) {
        cert.extensions.push(extension('1.3.6.1.5.5.7.1.1', new pki.InfoAccess({ accessDescriptions:
                                                                                 ocspUrls.map(value => new pki.AccessDescription({
                                                                                     accessMethod: '1.3.6.1.5.5.7.48.1', accessLocation: new pki.GeneralName({ type: 6, value })
                                                                                 }))
                                                                               }).toSchema()));
    }
    cert.extensions.push(...extraExtensions);
    await cert.sign(issuer?.keys.privateKey ?? keys.privateKey, hash, engine);
    return {
        cert, keys,
        pem: pem('CERTIFICATE', cert.toSchema().toBER()),
        key: pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', keys.privateKey))
    };
}

async function crl(issuer, { serials = [], start = Date.now() - 60000, end = Date.now() + 3600000,
                             missingNext = false, extensions = [], entries, signingKey, hash = 'SHA-256' } = {}) {
    const value = new pki.CertificateRevocationList({
        version: 1,
        issuer: issuer.cert.subject,
        thisUpdate: new pki.Time({ value: new Date(start) }),
        revokedCertificates: entries ?? serials.map(serial => new pki.RevokedCertificate({
            userCertificate: new asn1.Integer({ value: serial }),
            revocationDate: new pki.Time({ value: new Date(start) })
        }))
    });
    if (! missingNext) {
        value.nextUpdate = new pki.Time({ value: new Date(end) });
    }
    if (extensions.length) {
        value.crlExtensions = new pki.Extensions({ extensions });
    }
    await value.sign(signingKey ?? issuer.keys.privateKey, hash, engine);
    const der = Buffer.from(value.toSchema().toBER());
    return { der, pem: pem('X509 CRL', der), value };
}

async function ocsp(issuer, requestBytes, { signer = issuer, status = 'good', byKey = false,
                                            start = Date.now() - 60000, end = Date.now() + 3600000, producedAt = Date.now(),
                                            nonce = 'echo', responseStatus = 0, certID, extraResponses = [], responseExtensions = [],
                                            singleExtensions = [], includeSigner = true, signingKey, hash = 'SHA-256' } = {}) {
    const request = pki.OCSPRequest.fromBER(requestBytes);
    const basic = new pki.BasicOCSPResponse();
    basic.tbsResponseData.responderID = byKey ? new asn1.OctetString({ valueHex:
                                                                       await webcrypto.subtle.digest('SHA-1', signer.cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)
                                                                     }) : signer.cert.subject;
    basic.tbsResponseData.producedAt = new Date(producedAt);
    const single = new pki.SingleResponse({ certID: certID ?? request.tbsRequest.requestList[0].reqCert,
                                            thisUpdate: new Date(start), singleExtensions });
    if (end !== null) {
        single.nextUpdate = new Date(end);
    }
    single.certStatus = (status === 'revoked') ? new asn1.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 }, value: [ new asn1.GeneralizedTime({ valueDate: new Date(start) }) ]
    }) : new asn1.Primitive({ idBlock: { tagClass: 3, tagNumber: (status === 'good') ? 0 : 2 } });
    basic.tbsResponseData.responses = [ single, ...extraResponses ];
    basic.tbsResponseData.responseExtensions = [ ...responseExtensions ];
    if (nonce === 'echo') {
        basic.tbsResponseData.responseExtensions.push(...(request.tbsRequest.requestExtensions ?? []));
    } else if (nonce !== null) {
        basic.tbsResponseData.responseExtensions.push(extension('1.3.6.1.5.5.7.48.1.2', new asn1.OctetString({ valueHex: nonce })));
    }
    if (includeSigner) {
        basic.certs = [ signer.cert ];
    }
    await basic.sign(signingKey ?? signer.keys.privateKey, hash, engine);
    const envelope = new pki.OCSPResponse({ responseStatus: new asn1.Enumerated({ value: responseStatus }),
                                            responseBytes: new pki.ResponseBytes({ responseType: '1.3.6.1.5.5.7.48.1.1',
                                                                                   response: new asn1.OctetString({ valueHex: basic.toSchema().toBER() }) }) });
    return { der: Buffer.from(envelope.toSchema().toBER()), basic };
}

module.exports = { certificate, crl, ocsp, extension };
