'use strict';

const asn1 = require('asn1js');
const pki = require('pkijs');
const { cryptoEngine, parseDer, extensionsById, extensionValue, parseCertificate } = require('./pkiutils');

const MAX_CRL_BYTES = 16 * 1024 * 1024;

function distributionPoints(certificate) {
    const extension = extensionsById(certificate.extensions).get('2.5.29.31');
    if (! extension) {
        return undefined;
    }
    const points = extensionValue(extension, pki.CRLDistributionPoints).distributionPoints;
    if (! points.length) {
        throw new Error('Empty CRL distribution points extension');
    }
    return points.map(function(point) {
        return {
            urls: Array.isArray(point.distributionPoint) ?
                point.distributionPoint.filter(x => x.type === 6).map(x => x.value) : [],
            unsupported: (point.reasons !== undefined) || (point.cRLIssuer !== undefined)
        };
    });
}

function parseCrl(bytes) {
    if (bytes.length > MAX_CRL_BYTES) {
        throw new Error('CRL exceeds the 16 MiB size limit');
    }
    if (bytes.toString('ascii', 0, 32).trimStart().startsWith('-----BEGIN')) {
        const match = /^\s*-----BEGIN X509 CRL-----\s*([A-Za-z0-9+/=\r\n\t ]+)\s*-----END X509 CRL-----\s*$/.exec(bytes.toString('ascii'));
        if (! match) {
            throw new Error('Malformed PEM CRL; expected one X509 CRL block');
        }
        const encoded = match[1].replace(/\s/g, '');
        bytes = Buffer.from(encoded, 'base64');
        if (bytes.toString('base64') !== encoded) {
            throw new Error('Malformed base64 in PEM CRL');
        }
    }
    return parseDer(bytes, pki.CertificateRevocationList);
}

function checkValidity(crl, now = Date.now()) {
    const start = crl.thisUpdate.value.getTime();
    const end = crl.nextUpdate?.value.getTime();
    if (! Number.isFinite(start) || ! Number.isFinite(end) || (end <= start)) {
        throw new Error('CRL must have a valid thisUpdate and a later nextUpdate');
    }
    if (start > now) {
        throw new Error('CRL is not yet valid (thisUpdate is in the future)');
    }
    if (end <= now) {
        throw new Error('CRL has expired (nextUpdate has passed)');
    }
    return end;
}

function checkScope(crl, certificate, urls) {
    if (! [ 0, 1 ].includes(crl.version)) {
        throw new Error('Unsupported CRL version');
    }
    const extensions = extensionsById(crl.crlExtensions?.extensions);
    for (const extension of extensions.values()) {
        if (extension.extnID === '2.5.29.27') {
            throw new Error('Delta CRLs are unsupported; a complete CRL is required');
        }
        if (extension.critical && ! [ '2.5.29.28', '2.5.29.35', '2.5.29.20' ].includes(extension.extnID)) {
            throw new Error(`Unsupported critical CRL extension ${extension.extnID}`);
        }
    }
    const idpExtension = extensions.get('2.5.29.28');
    if (idpExtension) {
        const idp = extensionValue(idpExtension, pki.IssuingDistributionPoint);
        if (idp.indirectCRL || (idp.onlySomeReasons !== undefined) || idp.onlyContainsAttributeCerts) {
            throw new Error('Indirect, reason-limited and attribute-certificate CRLs are unsupported');
        }
        const basic = extensionsById(certificate.extensions).get('2.5.29.19');
        const isCA = basic ? extensionValue(basic, pki.BasicConstraints).cA : false;
        if ((idp.onlyContainsUserCerts && isCA) || (idp.onlyContainsCACerts && ! isCA)) {
            throw new Error('CRL scope does not cover this certificate type');
        }
        if (idp.distributionPoint !== undefined) {
            if (! Array.isArray(idp.distributionPoint) ||
                ! idp.distributionPoint.some(x => (x.type === 6) && urls.includes(x.value))) {
                throw new Error('CRL issuing distribution point does not match the effective distribution point');
            }
        }
    }
    return extensions;
}

async function validateCrl(crl, certificate, issuer, urls, now = Date.now()) {
    const nextUpdate = checkValidity(crl, now);
    const extensions = checkScope(crl, certificate, urls);
    if (! crl.issuer.isEqual(certificate.issuer) || ! crl.issuer.isEqual(issuer.subject)) {
        throw new Error('CRL issuer does not match the certificate issuer');
    }
    if (! await certificate.verify(issuer, cryptoEngine)) {
        throw new Error('CRL signing certificate did not issue the checked certificate');
    }
    if (! Buffer.from(crl.signature.toSchema().toBER()).equals(Buffer.from(crl.signatureAlgorithm.toSchema().toBER()))) {
        throw new Error('CRL signature algorithm identifiers disagree');
    }
    const hash = await cryptoEngine.getHashAlgorithm(crl.signatureAlgorithm);
    if (! [ 'SHA-256', 'SHA-384', 'SHA-512' ].includes(hash)) {
        throw new Error(`Unsupported or weak CRL signature algorithm: ${crl.signatureAlgorithm.algorithmId}`);
    }
    const issuerExtensions = extensionsById(issuer.extensions);
    const keyUsage = issuerExtensions.get('2.5.29.15');
    if (keyUsage) {
        const bits = extensionValue(keyUsage);
        if (! (bits instanceof asn1.BitString) || ! (bits.valueBlock.valueHexView[0] & 0x02)) {
            throw new Error('Issuer certificate key usage does not permit CRL signing');
        }
    }
    const authority = extensions.get('2.5.29.35');
    if (authority) {
        const aki = extensionValue(authority, pki.AuthorityKeyIdentifier);
        const ski = issuerExtensions.get('2.5.29.14');
        if (aki.keyIdentifier && ski &&
            ! Buffer.from(aki.keyIdentifier.valueBlock.valueHexView).equals(Buffer.from(extensionValue(ski).valueBlock.valueHexView))) {
            throw new Error('CRL authority key identifier does not match its issuer');
        }
        if (aki.authorityCertSerialNumber && ! aki.authorityCertSerialNumber.isEqual(issuer.serialNumber)) {
            throw new Error('CRL authority certificate serial number does not match its issuer');
        }
        if (aki.authorityCertIssuer && ! aki.authorityCertIssuer.some(x => (x.type === 4) && x.value.isEqual(issuer.issuer))) {
            throw new Error('CRL authority certificate issuer does not match its issuer certificate');
        }
    }
    const crlNumber = extensions.get('2.5.29.20');
    if (crlNumber && ! (extensionValue(crlNumber) instanceof asn1.Integer)) {
        throw new Error('Malformed CRL number');
    }
    if (! await crl.verify({ issuerCertificate: issuer }, cryptoEngine)) {
        throw new Error('CRL signature verification failed');
    }
    let revoked = false;
    for (const entry of crl.revokedCertificates ?? []) {
        for (const extension of extensionsById(entry.crlEntryExtensions?.extensions).values()) {
            if (extension.extnID === '2.5.29.29') {
                throw new Error('Indirect CRL certificateIssuer entries are unsupported');
            }
            if (extension.critical) {
                throw new Error(`Unsupported critical CRL entry extension ${extension.extnID}`);
            }
            if (extension.extnID === '2.5.29.21') {
                const reason = extensionValue(extension);
                if (! (reason instanceof asn1.Enumerated) || (reason.valueBlock.valueDec === 8)) {
                    throw new Error('Invalid revocation reason in a complete CRL');
                }
            }
        }
        if (entry.userCertificate.isEqual(certificate.serialNumber)) {
            revoked = true;
        }
    }
    checkValidity(crl);
    return { revoked, nextUpdate };
}

module.exports = { MAX_CRL_BYTES, parseCertificate, distributionPoints, parseCrl, validateCrl };
