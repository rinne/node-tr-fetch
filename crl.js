'use strict';

const { X509Certificate, constants, verify } = require('node:crypto');
const asn1 = require('asn1js');
const pki = require('pkijs');
const { cryptoEngine, parseDer, derElement, derRead, derHeader, oidString, extensionsById, extensionValue,
    parseCertificate } = require('./pkiutils');
const { DEFAULT_MAX_CRL_BYTES } = require('./options');
const { buildSerialIndex } = require('./serials');

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

function isPem(bytes) {
    return bytes.toString('ascii', 0, 32).trimStart().startsWith('-----BEGIN');
}

// One PEM X509 CRL block, strictly: canonical base64 and only whitespace
// around it.
function decodePem(bytes) {
    const match = /^\s*-----BEGIN X509 CRL-----\s*([A-Za-z0-9+/=\r\n\t ]+)\s*-----END X509 CRL-----\s*$/.exec(bytes.toString('ascii'));
    if (! match) {
        throw new Error('Malformed PEM CRL; expected one X509 CRL block');
    }
    const encoded = match[1].replace(/\s/g, '');
    const decoded = Buffer.from(encoded, 'base64');
    if (decoded.toString('base64') !== encoded) {
        throw new Error('Malformed base64 in PEM CRL');
    }
    return decoded;
}

// PKI.js decodes a CRL whose TBS consists of the given fields, followed by
// the trailer (signature algorithm and value): everything but the entries.
function buildCrlStub(fields, trailer) {
    const length = fields.reduce((sum, x) => sum + x.length, 0);
    const tbsHeader = derHeader(0x30, length);
    return parseDer(Buffer.concat([ derHeader(0x30, tbsHeader.length + length + trailer.length), tbsHeader, ...fields, trailer ]),
                    pki.CertificateRevocationList);
}

function parseCrl(bytes, maxBytes = DEFAULT_MAX_CRL_BYTES) {
    if (bytes.length > maxBytes) {
        throw new Error(`CRL exceeds maxCrlBytes (${maxBytes} bytes)`);
    }
    const size = bytes.length;
    if (isPem(bytes)) {
        bytes = decodePem(bytes);
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
    const crl = buildCrlStub(fields.filter(x => x !== entries).map(x => bytes.subarray(x.offset, x.end)),
                             bytes.subarray(tbs.end, outer.end));
    const scan = scanEntries(bytes, entries);
    return { crl, size, bytes, tbs: bytes.subarray(tbs.offset, tbs.end), entries,
        revokedCount: scan.count, entryProblem: scan.problem };
}

const OID_CERTIFICATE_ISSUER = Buffer.from([ 0x55, 0x1d, 0x1d ]);
const OID_REASON_CODE = Buffer.from([ 0x55, 0x1d, 0x15 ]);

function sameBytes(bytes, start, end, expected) {
    if ((end - start) !== expected.length) {
        return false;
    }
    for (let i = 0; i < expected.length; i++) {
        if (bytes[start + i] !== expected[i]) {
            return false;
        }
    }
    return true;
}

function sameRange(bytes, a, b, c, d) {
    if ((b - a) !== (d - c)) {
        return false;
    }
    for (let i = 0; i < (b - a); i++) {
        if (bytes[a + i] !== bytes[c + i]) {
            return false;
        }
    }
    return true;
}

// Reusable elements for walking entries: hundreds of thousands of entries
// must not create an object each. Walks are synchronous, so one set per walk.
function scratch() {
    return { entry: {}, number: {}, date: {}, extensions: {}, extension: {}, id: {}, value: {}, reason: {}, ids: [] };
}

function checkEntryExtensions(bytes, list, s) {
    let problem;
    s.ids.length = 0;
    for (let offset = list.start; offset < list.end;) {
        const extension = derRead(bytes, offset, list.end, s.extension);
        offset = extension.end;
        const id = derRead(bytes, extension.start, extension.end, s.id);
        let value = derRead(bytes, id.end, extension.end, s.value);
        let critical = false;
        if (value.tag === 0x01) {
            critical = (value.end > value.start) && (bytes[value.start] !== 0);
            value = derRead(bytes, value.end, extension.end, s.value);
        }
        if ((extension.tag !== 0x30) || (id.tag !== 0x06) || (value.tag !== 0x04) || (value.end !== extension.end)) {
            throw new Error('Malformed CRL entry extension');
        }
        // Object identifiers compare as bytes; strings only for messages.
        const extnID = () => oidString(bytes.subarray(id.start, id.end));
        for (let i = 0; i < s.ids.length; i += 2) {
            if (sameRange(bytes, s.ids[i], s.ids[i + 1], id.start, id.end)) {
                problem ??= `Duplicate extension ${extnID()}`;
            }
        }
        s.ids.push(id.start, id.end);
        if (sameBytes(bytes, id.start, id.end, OID_CERTIFICATE_ISSUER)) {
            problem ??= 'Indirect CRL certificateIssuer entries are unsupported';
        } else if (critical) {
            problem ??= `Unsupported critical CRL entry extension ${extnID()}`;
        } else if (sameBytes(bytes, id.start, id.end, OID_REASON_CODE)) {
            const reason = derRead(bytes, value.start, value.end, s.reason);
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
// is authenticated. With visit, call visit(start, end) for each serial in
// bytes instead of checking entry extensions again.
function scanEntries(bytes, entries, visit) {
    const s = scratch();
    let count = 0;
    let problem;
    for (let offset = entries?.start; offset < entries?.end;) {
        const result = readEntry(bytes, offset, entries.end, s, visit === undefined);
        problem ??= result.problem;
        offset = s.entry.end;
        count++;
        visit?.(s.number.start, s.number.end);
    }
    return { count, problem };
}

// Check one revoked entry at bytes[offset], within end. Fills s.entry and
// s.number (the serial); structural errors throw, and with checkExtensions,
// the first unsupported extension is returned as problem.
function readEntry(bytes, offset, end, s, checkExtensions) {
    const entry = derRead(bytes, offset, end, s.entry);
    const number = derRead(bytes, entry.start, entry.end, s.number);
    const date = derRead(bytes, number.end, entry.end, s.date);
    let next = date.end;
    let problem;
    if ((entry.tag !== 0x30) || (number.tag !== 0x02) || ((date.tag !== 0x17) && (date.tag !== 0x18))) {
        throw new Error('Malformed revoked certificate entry');
    }
    if (next < entry.end) {
        const extensions = derRead(bytes, next, entry.end, s.extensions);
        if (extensions.tag !== 0x30) {
            throw new Error('Malformed revoked certificate entry');
        }
        if (checkExtensions) {
            problem = checkEntryExtensions(bytes, extensions, s);
        }
        next = extensions.end;
    }
    if (next !== entry.end) {
        throw new Error('Malformed revoked certificate entry');
    }
    return { problem };
}

const RSA_PSS = '1.2.840.113549.1.1.10';
const MGF1 = '1.2.840.113549.1.1.8';
// Signature algorithms and the issuer key types they need. The hash is
// checked separately and must be SHA-256, SHA-384 or SHA-512.
const SIGNATURE_KEY_TYPES = {
    '1.2.840.113549.1.1.11': [ 'rsa' ],
    '1.2.840.113549.1.1.12': [ 'rsa' ],
    '1.2.840.113549.1.1.13': [ 'rsa' ],
    [RSA_PSS]: [ 'rsa', 'rsa-pss' ],
    '1.2.840.10045.4.3.2': [ 'ec' ],
    '1.2.840.10045.4.3.3': [ 'ec' ],
    '1.2.840.10045.4.3.4': [ 'ec' ]
};

// The issuer key, with RSA-PSS padding when needed, for verifying the CRL
// signature; undefined when the algorithm does not suit the issuer key or the
// signature value is malformed.
function signatureOptions(crl, issuerDer) {
    const algorithm = crl.signatureAlgorithm.algorithmId;
    const key = new X509Certificate(issuerDer).publicKey;
    if (! SIGNATURE_KEY_TYPES[algorithm]?.includes(key.asymmetricKeyType) || crl.signatureValue.valueBlock.unusedBits) {
        return undefined;
    }
    let options = key;
    if (algorithm === RSA_PSS) {
        const params = new pki.RSASSAPSSParams({ schema: crl.signatureAlgorithm.algorithmParams });
        const mgfHash = (params.maskGenAlgorithm.algorithmId === MGF1) ?
            new pki.AlgorithmIdentifier({ schema: params.maskGenAlgorithm.algorithmParams }).algorithmId : undefined;
        // Node applies MGF1 with the signature hash; nothing else is accepted.
        if ((mgfHash !== params.hashAlgorithm.algorithmId) || (params.trailerField !== 1)) {
            throw new Error('Unsupported RSA-PSS parameters in CRL signature');
        }
        options = { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: params.saltLength };
    }
    return options;
}

function nodeHash(hash) {
    return hash.replace('-', '').toLowerCase();
}

// Node's synchronous verify hashes the TBS bytes where they are. Web Crypto
// and asynchronous verification copy them first, which for a CRL of tens of
// megabytes doubles its memory. X.509 ECDSA signatures are already DER, the
// form Node expects.
function crlSignatureValid(tbs, crl, issuerDer, hash) {
    const options = signatureOptions(crl, issuerDer);
    try {
        return (options !== undefined) && verify(nodeHash(hash), tbs, options, crl.signatureValue.valueBlock.valueHexView);
    } catch (_) {
        return false;
    }
}

function checkDates(thisUpdate, nextUpdate, now) {
    if (thisUpdate > now) {
        throw new Error('CRL is not yet valid (thisUpdate is in the future)');
    }
    if (nextUpdate <= now) {
        throw new Error('CRL has expired (nextUpdate has passed)');
    }
}

function certificateDer(certificate) {
    return Buffer.from(certificate.toSchema().toBER());
}

// An authenticated CRL reduced to what checking a certificate needs: the
// revoked serials, the validity period and the scope. It does not retain the
// CRL itself, and serves only certificates of the issuer that signed it.
class RevocationList {
    #issuerCertificate;

    constructor(fields) {
        this.#issuerCertificate = fields.issuerCertificate;
        this.issuer = fields.issuer;
        this.thisUpdate = fields.thisUpdate;
        this.nextUpdate = fields.nextUpdate;
        this.scope = fields.scope;
        this.serials = fields.serials;
        this.revokedCount = fields.revokedCount;
        this.size = fields.size;
        Object.freeze(this);
    }

    signedBy(issuer) {
        return certificateDer(issuer).equals(this.#issuerCertificate);
    }
}

// Checks of a CRL's header (everything but the entries and the signature)
// against its issuer: structure, scope support, issuer binding, signing
// permission and algorithms. Returns what checking certificates needs.
async function checkCrlHeader(crl, issuer) {
    const thisUpdate = crl.thisUpdate.value.getTime();
    const nextUpdate = crl.nextUpdate?.value.getTime();
    if (! Number.isFinite(thisUpdate) || ! Number.isFinite(nextUpdate) || (nextUpdate <= thisUpdate)) {
        throw new Error('CRL must have a valid thisUpdate and a later nextUpdate');
    }
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
    const scope = { onlyUserCertificates: false, onlyCaCertificates: false, distributionPoints: undefined };
    const idpExtension = extensions.get('2.5.29.28');
    if (idpExtension) {
        const idp = extensionValue(idpExtension, pki.IssuingDistributionPoint);
        if (idp.indirectCRL || (idp.onlySomeReasons !== undefined) || idp.onlyContainsAttributeCerts) {
            throw new Error('Indirect, reason-limited and attribute-certificate CRLs are unsupported');
        }
        scope.onlyUserCertificates = !! idp.onlyContainsUserCerts;
        scope.onlyCaCertificates = !! idp.onlyContainsCACerts;
        if (idp.distributionPoint !== undefined) {
            // Only URI names can match; other name forms never do.
            scope.distributionPoints = Array.isArray(idp.distributionPoint) ?
                idp.distributionPoint.filter(x => x.type === 6).map(x => x.value) : [];
        }
    }
    Object.freeze(scope.distributionPoints);
    if (! crl.issuer.isEqual(issuer.subject)) {
        throw new Error('CRL issuer does not match the certificate issuer');
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
    return { issuer: crl.issuer, thisUpdate, nextUpdate, scope: Object.freeze(scope), hash };
}

// Everything that depends only on the CRL and its issuer: the header checks,
// the signature and the entries. Runs once per downloaded CRL; the result
// can be cached for the issuer.
async function authenticateCrl(parsed, issuer) {
    const crl = parsed.crl;
    const { thisUpdate, nextUpdate, scope, hash } = await checkCrlHeader(crl, issuer);
    // The signature covers the original TBS bytes, including the entries.
    const issuerDer = certificateDer(issuer);
    if (! crlSignatureValid(parsed.tbs, crl, issuerDer, hash)) {
        throw new Error('CRL signature verification failed');
    }
    if (parsed.entryProblem) {
        throw new Error(parsed.entryProblem);
    }
    // Only an authenticated CRL is worth indexing.
    const serials = buildSerialIndex(parsed.bytes, visit => scanEntries(parsed.bytes, parsed.entries, visit));
    return new RevocationList({ issuerCertificate: issuerDer, issuer: crl.issuer, thisUpdate, nextUpdate,
                                scope, serials, revokedCount: parsed.revokedCount, size: parsed.size });
}

function isCaCertificate(certificate) {
    const basic = extensionsById(certificate.extensions).get('2.5.29.19');
    return basic ? !! extensionValue(basic, pki.BasicConstraints).cA : false;
}

// Whether a CRL's scope covers a certificate of the given type, reached
// through the given distribution point URLs. Throws if not.
function checkScope(scope, isCA, urls) {
    if ((scope.onlyUserCertificates && isCA) || (scope.onlyCaCertificates && ! isCA)) {
        throw new Error('CRL scope does not cover this certificate type');
    }
    if ((scope.distributionPoints !== undefined) && ! scope.distributionPoints.some(x => urls.includes(x))) {
        throw new Error('CRL issuing distribution point does not match the effective distribution point');
    }
}

// Everything that depends on the checked certificate or the current time,
// given an authenticated CRL's header details. Throws if the CRL does not
// apply to the certificate.
async function checkCertificateAgainst(details, certificate, issuer, urls, now = Date.now()) {
    checkDates(details.thisUpdate, details.nextUpdate, now);
    checkScope(details.scope, isCaCertificate(certificate), urls);
    if (! details.issuer.isEqual(certificate.issuer)) {
        throw new Error('CRL issuer does not match the certificate issuer');
    }
    if (! await certificate.verify(issuer, cryptoEngine)) {
        throw new Error('CRL signing certificate did not issue the checked certificate');
    }
}

// Runs on every use of a revocation list, including cached lists.
async function checkRevocationList(list, certificate, issuer, urls, now = Date.now()) {
    if (! list.signedBy(issuer)) {
        throw new Error('CRL was authenticated for a different issuer certificate');
    }
    await checkCertificateAgainst(list, certificate, issuer, urls, now);
    const revoked = list.serials.has(Buffer.from(certificate.serialNumber.valueBlock.valueHexView));
    // Checks above can take time; the list must still be valid now.
    checkDates(list.thisUpdate, list.nextUpdate, Date.now());
    return { revoked, nextUpdate: list.nextUpdate };
}

async function validateCrl(parsed, certificate, issuer, urls, now = Date.now()) {
    return checkRevocationList(await authenticateCrl(parsed, issuer), certificate, issuer, urls, now);
}

module.exports = { RevocationList, parseCertificate, distributionPoints, parseCrl, authenticateCrl, checkRevocationList,
    validateCrl, isPem, decodePem, buildCrlStub, readEntry, scratch, checkCrlHeader, signatureOptions, nodeHash, certificateDer,
    isCaCertificate, checkScope, checkDates, checkCertificateAgainst };
