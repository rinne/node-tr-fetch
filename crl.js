'use strict';

const asn1 = require('asn1js');
const pki = require('pkijs');
const { cryptoEngine, parseDer, derElement, derHeader, oidString, extensionsById, extensionValue,
    parseCertificate } = require('./pkiutils');

const MAX_CRL_BYTES = 16 * 1024 * 1024;
const TIME_TAGS = [ 0x17, 0x18 ];

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
    const outer = derElement(bytes, 0);
    if (outer.end !== bytes.length) {
        throw new Error('Malformed ASN.1 data: trailing bytes');
    }
    const tbs = derElement(bytes, outer.start, outer.end);
    if ((outer.tag !== 0x30) || (tbs.tag !== 0x30)) {
        throw new Error('Malformed CRL structure');
    }
    const fields = [];
    for (let offset = tbs.start; offset < tbs.end; offset = fields.at(-1).end) {
        fields.push(derElement(bytes, offset, tbs.end));
    }
    // version, signature, issuer, thisUpdate, nextUpdate, revokedCertificates
    let index = (fields[0]?.tag === 0x02) ? 3 : 2;
    index += TIME_TAGS.includes(fields[index + 1]?.tag) ? 2 : 1;
    const entries = (fields[index]?.tag === 0x30) ? fields[index] : undefined;
    // Decoding every revoked entry into an ASN.1 object tree takes hundreds of
    // bytes of memory per encoded byte, so large CRLs could exhaust the heap.
    // PKI.js decodes the rest; the entries are scanned in place.
    const headerFields = fields.filter(x => x !== entries).map(x => bytes.subarray(x.offset, x.end));
    const headerLength = headerFields.reduce((sum, x) => sum + x.length, 0);
    const trailer = bytes.subarray(tbs.end, outer.end);
    const tbsHeader = derHeader(0x30, headerLength);
    const crl = parseDer(Buffer.concat([ derHeader(0x30, tbsHeader.length + headerLength + trailer.length),
        tbsHeader, ...headerFields, trailer ]), pki.CertificateRevocationList);
    const scan = scanEntries(bytes, entries);
    return { crl, bytes, tbs: bytes.subarray(tbs.offset, tbs.end), entries,
        revokedCount: scan.count, entryProblem: scan.problem };
}

function checkEntryExtensions(bytes, list) {
    const seen = new Set();
    let problem;
    for (let offset = list.start; offset < list.end;) {
        const extension = derElement(bytes, offset, list.end);
        offset = extension.end;
        const id = derElement(bytes, extension.start, extension.end);
        let value = derElement(bytes, id.end, extension.end);
        let critical = false;
        if (value.tag === 0x01) {
            critical = (value.end > value.start) && (bytes[value.start] !== 0);
            value = derElement(bytes, value.end, extension.end);
        }
        if ((extension.tag !== 0x30) || (id.tag !== 0x06) || (value.tag !== 0x04) || (value.end !== extension.end)) {
            throw new Error('Malformed CRL entry extension');
        }
        const extnID = oidString(bytes.subarray(id.start, id.end));
        if (seen.has(extnID)) {
            problem ??= `Duplicate extension ${extnID}`;
        }
        seen.add(extnID);
        if (extnID === '2.5.29.29') {
            problem ??= 'Indirect CRL certificateIssuer entries are unsupported';
        } else if (critical) {
            problem ??= `Unsupported critical CRL entry extension ${extnID}`;
        } else if (extnID === '2.5.29.21') {
            const reason = derElement(bytes, value.start, value.end);
            let code = 0;
            for (let i = reason.start; i < reason.end; i++) {
                code = (code * 256) + bytes[i];
            }
            if ((reason.tag !== 0x0a) || (reason.end !== value.end) || (reason.end === reason.start) || (code === 8)) {
                problem ??= 'Invalid revocation reason in a complete CRL';
            }
        }
    }
    return problem;
}

// Walk the revoked entries without decoding them into objects. Structural
// errors throw; the first unsupported entry is reported for use after the CRL
// is authenticated. With a serial, also report whether it is listed.
function scanEntries(bytes, entries, serial) {
    let count = 0;
    let problem;
    let revoked = false;
    for (let offset = entries?.start; offset < entries?.end;) {
        const entry = derElement(bytes, offset, entries.end);
        offset = entry.end;
        const number = derElement(bytes, entry.start, entry.end);
        const date = derElement(bytes, number.end, entry.end);
        let next = date.end;
        if ((entry.tag !== 0x30) || (number.tag !== 0x02) || ! TIME_TAGS.includes(date.tag)) {
            throw new Error('Malformed revoked certificate entry');
        }
        if (next < entry.end) {
            const extensions = derElement(bytes, next, entry.end);
            if (extensions.tag !== 0x30) {
                throw new Error('Malformed revoked certificate entry');
            }
            if (serial === undefined) {
                problem ??= checkEntryExtensions(bytes, extensions);
            }
            next = extensions.end;
        }
        if (next !== entry.end) {
            throw new Error('Malformed revoked certificate entry');
        }
        count++;
        if ((serial !== undefined) && bytes.subarray(number.start, number.end).equals(serial)) {
            revoked = true;
        }
    }
    return { count, problem, revoked };
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

async function validateCrl(parsed, certificate, issuer, urls, now = Date.now()) {
    const crl = parsed.crl;
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
    // The signature covers the original TBS bytes, including the entries.
    if (! await cryptoEngine.verifyWithPublicKey(parsed.tbs, crl.signatureValue, issuer.subjectPublicKeyInfo, crl.signatureAlgorithm)) {
        throw new Error('CRL signature verification failed');
    }
    if (parsed.entryProblem) {
        throw new Error(parsed.entryProblem);
    }
    const serial = Buffer.from(certificate.serialNumber.valueBlock.valueHexView);
    const { revoked } = scanEntries(parsed.bytes, parsed.entries, serial);
    checkValidity(crl);
    return { revoked, nextUpdate };
}

module.exports = { MAX_CRL_BYTES, parseCertificate, distributionPoints, parseCrl, validateCrl };
