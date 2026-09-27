'use strict';

const asn1 = require('asn1js');
const pki = require('pkijs');
const { createHash, randomBytes, X509Certificate } = require('node:crypto');
const { cryptoEngine, parseDer, parseCertificate, extensionsById, extensionValue } = require('./pkiutils');
const { downloadOcsp, networkUrl } = require('./download');
const { TrFetchOcspError, applyPolicy } = require('./errors');
const { debugUrl } = require('./debug');
const { ExpiringCache } = require('./cache');

function ocspEntry(key) {
    const [issuer, certificate, ...url] = key.split(':');
    return { issuer, certificate: certificate.slice(0, 16), source: debugUrl(url.join(':')) };
}

// Authenticated 'good' and 'revoked' results by issuer, certificate and
// responder URL, until the earlier of the response's nextUpdate (bounded by
// its signer certificate) and the TTL. Never errors or 'unknown'.
const cache = new ExpiringCache('OCSP cache', ocspEntry);

const OCSP_ACCESS = '1.3.6.1.5.5.7.48.1';
const NONCE = '1.3.6.1.5.5.7.48.1.2';
const NO_CHECK = '1.3.6.1.5.5.7.48.1.5';
const OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

function ocspUris(certificate) {
    const extension = extensionsById(certificate.extensions).get('1.3.6.1.5.5.7.1.1');
    if (! extension) {
        return [];
    }
    const access = extensionValue(extension, pki.InfoAccess);
    return access.accessDescriptions.filter(x => x.accessMethod === OCSP_ACCESS)
        .map(x => (x.accessLocation.type === 6) ? x.accessLocation.value : '');
}

async function createOcspRequest(certificate, issuer) {
    // SHA-1 here identifies the issuer; response signatures require SHA-2.
    const certID = await pki.CertID.create(certificate, { issuerCertificate: issuer, hashAlgorithm: 'SHA-1' }, cryptoEngine);
    const nonce = randomBytes(32);
    const request = new pki.OCSPRequest();
    request.tbsRequest.requestList = [ new pki.Request({ reqCert: certID }) ];
    request.tbsRequest.requestExtensions = [ new pki.Extension({
        extnID: NONCE,
        extnValue: new asn1.OctetString({ valueHex: nonce }).toBER()
    }) ];
    return { certID, nonce, bytes: Buffer.from(request.toSchema(true).toBER()) };
}

function checkExtensions(extensions, allowedCritical = []) {
    const byId = extensionsById(extensions);
    for (const extension of byId.values()) {
        if (extension.critical && ! allowedCritical.includes(extension.extnID)) {
            throw new Error(`Unsupported critical OCSP extension ${extension.extnID}`);
        }
    }
    return byId;
}

async function authorizeSigner(signer, issuer, producedAt, now) {
    const before = signer.notBefore.value.getTime();
    const after = signer.notAfter.value.getTime();
    if (! Number.isFinite(before) || ! Number.isFinite(after) ||
        (before > now) || (after <= now) || (producedAt < before) || (producedAt > after)) {
        throw new Error('OCSP signer certificate is expired or not yet valid');
    }
    if (Buffer.from(signer.toSchema().toBER()).equals(Buffer.from(issuer.toSchema().toBER()))) {
        return after;
    }
    if (! [ 'SHA-256', 'SHA-384', 'SHA-512' ].includes(cryptoEngine.getHashAlgorithm(signer.signatureAlgorithm))) {
        throw new Error('Unsupported or weak OCSP delegated signer certificate signature');
    }
    const key = new X509Certificate(Buffer.from(signer.toSchema().toBER())).publicKey;
    if ([ 'rsa', 'rsa-pss' ].includes(key.asymmetricKeyType) && (key.asymmetricKeyDetails.modulusLength < 2048)) {
        throw new Error('OCSP delegated signer RSA key must be at least 2048 bits');
    }
    if (! signer.issuer.isEqual(issuer.subject) || ! await signer.verify(issuer, cryptoEngine)) {
        throw new Error('OCSP delegated signer was not issued directly by the checked certificate issuer');
    }
    const extensions = checkExtensions(signer.extensions, [ '2.5.29.15', '2.5.29.19', '2.5.29.37' ]);
    const eku = extensions.get('2.5.29.37');
    if (! eku || ! extensionValue(eku, pki.ExtKeyUsage).keyPurposes.includes(OCSP_SIGNING)) {
        throw new Error('OCSP delegated signer lacks the OCSP signing extended key usage');
    }
    const usage = extensions.get('2.5.29.15');
    if (usage) {
        const bits = extensionValue(usage);
        if (! (bits instanceof asn1.BitString) || ! (bits.valueBlock.valueHexView[0] & 0x80)) {
            throw new Error('OCSP delegated signer key usage does not permit digital signatures');
        }
    }
    const basic = extensions.get('2.5.29.19');
    if (basic && extensionValue(basic, pki.BasicConstraints).cA) {
        throw new Error('OCSP delegated signer must be an end-entity responder certificate');
    }
    // Without no-check, the responder certificate needs its own revocation
    // checking. Do not silently trust it or recursively query the same responder.
    const noCheck = extensions.get(NO_CHECK);
    if (! noCheck || ! (extensionValue(noCheck) instanceof asn1.Null)) {
        throw new Error('OCSP delegated signer without a valid id-pkix-ocsp-nocheck extension is unsupported');
    }
    return after;
}

async function validateOcspResponse(bytes, request, certificate, issuer, now = Date.now(), debug) {
    if (bytes.length > 1024 * 1024) {
        throw new Error('OCSP response exceeds the 1 MiB size limit');
    }
    const envelope = parseDer(bytes, pki.OCSPResponse);
    const status = envelope.responseStatus.valueBlock.valueDec;
    if (status !== 0) {
        const names = { 1: 'malformedRequest', 2: 'internalError', 3: 'tryLater', 5: 'sigRequired', 6: 'unauthorized' };
        throw new Error(`OCSP responder returned ${names[status] ?? 'unrecognized status'} (${status})`);
    }
    if (envelope.responseBytes?.responseType !== '1.3.6.1.5.5.7.48.1.1') {
        throw new Error('OCSP response has no supported BasicOCSPResponse');
    }
    const basic = parseDer(envelope.responseBytes.response.valueBlock.valueHexView, pki.BasicOCSPResponse);
    const data = basic.tbsResponseData;
    debug?.('OCSP response parsed', { responses: data.responses.length });
    if ((data.version ?? 0) !== 0) {
        throw new Error('Unsupported OCSP response version');
    }
    const producedAt = data.producedAt.getTime();
    if (! Number.isFinite(producedAt) || (producedAt > now)) {
        throw new Error('OCSP producedAt is invalid or in the future');
    }
    const extensions = checkExtensions(data.responseExtensions, [ NONCE ]);
    const nonceExtension = extensions.get(NONCE);
    if (nonceExtension) {
        const nonce = extensionValue(nonceExtension);
        if (! (nonce instanceof asn1.OctetString) ||
            ! Buffer.from(nonce.valueBlock.valueHexView).equals(request.nonce)) {
            throw new Error('OCSP response nonce does not match the request');
        }
    }
    const matches = data.responses.filter(x => x.certID.isEqual(request.certID));
    if (matches.length !== 1) {
        throw new Error('OCSP response must contain exactly one matching certificate ID (issuer and serial)');
    }
    const single = matches[0];
    checkExtensions(single.singleExtensions);
    const thisUpdate = single.thisUpdate.getTime();
    // Some responders omit nextUpdate. Such responses have a maximum age of
    // five minutes here, even if the transport just retrieved them successfully.
    const nextUpdate = single.nextUpdate?.getTime() ?? thisUpdate + 300000;
    if (! Number.isFinite(thisUpdate) || ! Number.isFinite(nextUpdate) ||
        (thisUpdate > now) || (thisUpdate > producedAt) || (nextUpdate <= thisUpdate)) {
        throw new Error('OCSP response has invalid or future validity times');
    }
    if (nextUpdate <= now) {
        throw new Error('OCSP response has expired or is stale');
    }
    if (! certificate.issuer.isEqual(issuer.subject) || ! await certificate.verify(issuer, cryptoEngine)) {
        throw new Error('OCSP issuer did not issue the checked certificate');
    }
    const hash = cryptoEngine.getHashAlgorithm(basic.signatureAlgorithm);
    if (! [ 'SHA-256', 'SHA-384', 'SHA-512' ].includes(hash)) {
        throw new Error(`Unsupported or weak OCSP signature algorithm: ${basic.signatureAlgorithm.algorithmId}`);
    }
    const signers = [ issuer, ...(basic.certs ?? []) ];
    if (signers.length > 33) {
        throw new Error('OCSP response includes too many signer certificates');
    }
    const candidates = await pki.BasicOCSPResponse.collectResponderCandidates(signers, data.responderID, cryptoEngine);
    let authenticated = false;
    let signerExpiry = Infinity;
    let signerError;
    for (const index of candidates) {
        try {
            signerExpiry = await authorizeSigner(signers[index], issuer, producedAt, now);
            if (! await basic.verifyResponseSignature(signers[index], cryptoEngine)) {
                throw new Error('OCSP response signature verification failed');
            }
            authenticated = true;
            break;
        } catch (error) {
            signerError = error;
        }
    }
    if (! authenticated) {
        throw signerError ?? new Error('No authorized OCSP signer matches the responder ID');
    }
    const certStatus = single.certStatus;
    const tag = certStatus.idBlock.tagNumber;
    if ((certStatus.idBlock.tagClass !== 3) || ! [ 0, 1, 2 ].includes(tag) ||
        ((tag !== 1) && (certStatus.idBlock.isConstructed || certStatus.valueBlock.valueHexView.length))) {
        throw new Error('Malformed OCSP certificate status');
    }
    if (tag === 1) {
        const time = certStatus.valueBlock.value?.[0];
        if (! (time instanceof asn1.GeneralizedTime) || (time.toDate().getTime() > producedAt)) {
            throw new Error('Malformed or future OCSP revocation time');
        }
    }
    const expiresAt = Math.min(nextUpdate, signerExpiry);
    if (Date.now() >= expiresAt) {
        throw new Error('OCSP response or signer certificate expired during validation');
    }
    return { status: [ 'good', 'revoked', 'unknown' ][tag], nextUpdate: expiresAt };
}

// Check a certificate with OCSP. Returns { answered, nextUpdate } for an
// authenticated good or revoked status, applying the rejectedCertificate
// policy if revoked. Otherwise, including for an unknown status, returns
// { answered: false, failures }: the conditions whose policies the caller
// applies, or drops when another check answers.
async function checkOcspCertificate(peer, hostname, options, signal, leaf, debug) {
    const policy = options.ocspPolicy;
    const label = `${leaf ? 'server' : 'intermediate CA'} certificate ${peer.serialNumber} for ${JSON.stringify(hostname)}`;
    function issue(key, message, uri, cause, ocspStatus) {
        debug?.('OCSP condition detected', { policy: key, configuredAction: policy[key], reason: message,
                                             source: (uri === undefined) ? undefined : debugUrl(uri), result: ocspStatus });
        return new TrFetchOcspError(key, `${message} (${label})`, {
            hostname, serialNumber: peer.serialNumber, fingerprint256: peer.fingerprint256, ocspUri: uri, ocspStatus
        }, cause);
    }
    function responderDebugFor(uri) {
        return debug ? (event, details) => debug(event, { source: debugUrl(uri), ...details }) : undefined;
    }
    function completed(result, uri, responderDebug) {
        responderDebug?.('OCSP check completed', { result: result.status, authenticated: true,
                                                   policy: 'rejectedCertificate', configuredAction: policy.rejectedCertificate,
                                                   action: (result.status === 'good') ? 'continue' : policy.rejectedCertificate,
                                                   nextUpdate: result.nextUpdate, cached: result.cached });
        if (result.status !== 'good') {
            const rejected = issue('rejectedCertificate', `OCSP rejected certificate: responder reports ${result.status}`, uri, undefined,
                                   result.status);
            if (result.status === 'unknown') {
                // The responder does not know the certificate: no status.
                return { answered: false, failures: [ rejected ] };
            }
            applyPolicy(policy, rejected, responderDebug, options.warningCb);
        }
        return { answered: true, nextUpdate: result.nextUpdate };
    }
    let certificate, uris, issuer, request;
    try {
        certificate = parseCertificate(peer.raw);
        uris = (leaf && (options.ocspUri !== undefined)) ? [ options.ocspUri ] : ocspUris(certificate);
        for (const uri of uris) {
            debug?.((leaf && (options.ocspUri !== undefined)) ? 'OCSP URI override selected' : 'OCSP URI detected in certificate', {
                source: debugUrl(uri)
            });
        }
    } catch (cause) {
        return { answered: false, failures: [ issue('rejectedCertificate', `Cannot read OCSP certificate information: ${cause.message}`,
                                                    undefined, cause, 'invalid-response') ] };
    }
    if (! uris.length) {
        return { answered: false, failures: [ issue('missingOcspUri', 'Missing OCSP responder URI') ] };
    }
    // Cached results are keyed by issuer, certificate and responder URL, and
    // are looked up before an OCSP request is built.
    const identity = (peer.issuerCertificate?.raw === undefined) ? undefined :
        createHash('sha256').update(peer.issuerCertificate.raw).digest('hex') + ':' + createHash('sha256').update(peer.raw).digest('hex') + ':';
    const limits = [ policy.ocspCacheSize, policy.ocspCacheTTL ];
    for (const uri of (identity === undefined) ? [] : uris.slice(0, 32)) {
        const cached = cache.get(identity + uri, ...limits, Date.now(), debug);
        if (cached) {
            return completed({ ...cached, cached: true }, uri, responderDebugFor(uri));
        }
    }
    try {
        if (! peer.issuerCertificate?.raw) {
            throw new Error('The verified TLS chain does not expose the issuer certificate');
        }
        issuer = parseCertificate(peer.issuerCertificate.raw);
        request = await createOcspRequest(certificate, issuer);
    } catch (cause) {
        return { answered: false, failures: [ issue('rejectedCertificate', `Cannot prepare OCSP verification: ${cause.message}`,
                                                    undefined, cause, 'invalid-response') ] };
    }
    const failures = [];
    for (const uri of uris.slice(0, 32)) {
        signal?.throwIfAborted();
        const responderDebug = responderDebugFor(uri);
        const fetchedAt = Date.now();
        let bytes;
        try {
            bytes = await downloadOcsp(networkUrl(uri, 'OCSP responder'), request.bytes, signal, responderDebug);
        } catch (cause) {
            signal?.throwIfAborted();
            failures.push(issue('unreachableOcspUri', `Unreachable OCSP responder: ${cause.message}`, uri, cause));
            continue;
        }
        let result;
        try {
            result = await validateOcspResponse(bytes, request, certificate, issuer, Date.now(), responderDebug);
        } catch (cause) {
            failures.push(issue('rejectedCertificate', `Invalid OCSP response: ${cause.message}`, uri, cause, 'invalid-response'));
            continue;
        }
        if (result.status !== 'unknown') {
            cache.set(identity + uri, { status: result.status, nextUpdate: result.nextUpdate }, result.nextUpdate, fetchedAt,
                      ...limits, Date.now(), debug);
        }
        return completed(result, uri, responderDebug);
    }
    if (uris.length > 32) {
        failures.push(issue('unreachableOcspUri', 'OCSP responder URI lookup limit (32) exceeded'));
    }
    return { answered: false, failures };
}

module.exports = { ocspUris, createOcspRequest, validateOcspResponse, checkOcspCertificate };
