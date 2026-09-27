'use strict';

const { createHash } = require('node:crypto');
const { parseCertificate, distributionPoints, parseCrl, authenticateCrl, checkRevocationList, checkCertificateAgainst,
    checkDates, checkScope, isCaCertificate } = require('./crl');
const { authenticateCrlStream } = require('./crlstream');
const { networkUrl, downloadCrl } = require('./download');
const { TrFetchCrlError, TrFetchOcspError, applyPolicy } = require('./errors');
const { checkOcspCertificate } = require('./ocsp');
const CrlCache = require('./cache');
const { CrlResultCache } = require('./cache');
const { debugUrl } = require('./debug');

const cache = new CrlCache();
const resultCache = new CrlResultCache();

function sourceLabel(value) {
    try {
        const url = new URL(value);
        return JSON.stringify(url.origin + url.pathname);
    } catch (_) {
        return '(invalid URL)';
    }
}

async function checkCertificate(peer, hostname, options, signal, override, debug) {
    const details = { hostname, serialNumber: peer.serialNumber, fingerprint256: peer.fingerprint256 };
    const certificateType = override ? 'server' : 'intermediate CA';
    const label = `${certificateType} certificate ${peer.serialNumber} for ${JSON.stringify(hostname)}`;
    function issue(key, message, cause, distributionPoint) {
        debug?.('CRL condition detected', { policy: key, configuredAction: options.policy[key],
                                            reason: message, source: (distributionPoint === undefined) ? undefined : debugUrl(distributionPoint) });
        return new TrFetchCrlError(key, `${message} (${label})`, { ...details, distributionPoint }, cause);
    }
    let certificate, points;
    const forcedCrl = override ? options.crl : undefined;
    const forcedPoint = override ? options.distributionPoint : undefined;
    try {
        certificate = parseCertificate(peer.raw);
        if (forcedCrl !== undefined) {
            debug?.('CRL data override selected', { bytes: forcedCrl.length });
            points = [ { urls: [] } ];
        } else if (forcedPoint !== undefined) {
            debug?.('CRL distribution point override selected', { source: debugUrl(forcedPoint) });
            points = [ { urls: [ forcedPoint ] } ];
        } else {
            points = distributionPoints(certificate);
            for (const point of points ?? []) {
                debug?.('CRL distribution point detected in certificate', {
                    sources: point.urls.map(debugUrl), unsupportedScope: point.unsupported
                });
            }
        }
    } catch (cause) {
        applyPolicy(options.policy, issue('invalidCrl', `Cannot read certificate CRL information: ${cause.message}`, cause), debug, options.warningCb);
        return;
    }
    if (points === undefined) {
        applyPolicy(options.policy, issue('missingCrlDistributionPoint', 'Missing CRL distribution point'), debug, options.warningCb);
        return;
    }
    let issuer;
    try {
        if (! peer.issuerCertificate?.raw) {
            throw new Error('The verified TLS chain does not expose the issuer certificate');
        }
        issuer = parseCertificate(peer.issuerCertificate.raw);
    } catch (cause) {
        applyPolicy(options.policy, issue('invalidCrl', `Cannot authenticate CRL: ${cause.message}`, cause), debug, options.warningCb);
        return;
    }
    const issuerId = createHash('sha256').update(peer.issuerCertificate.raw).digest('hex');
    const certificateId = createHash('sha256').update(peer.raw).digest('hex');
    // The CRL cache and the per-certificate result cache have their own
    // sizes and share the TTL.
    const limits = [ options.policy.crlCacheSize, options.policy.crlCacheTTL ];
    const resultLimits = [ options.policy.crlCertificateCacheSize, options.policy.crlCacheTTL ];
    function unreachable(source, cause) {
        failures.push(issue('unreachableCrlDistributionPoint',
                            `Unreachable CRL distribution point ${sourceLabel(source)}: ${cause.message}`, cause, source));
    }
    function invalid(source, cause) {
        failures.push(issue('invalidCrl',
                            `Invalid CRL from ${(source === undefined) ? 'trFetchCrlOverride' : sourceLabel(source)}: ${cause.message}`, cause, source));
    }

    // crlCacheScope 'crl': the whole CRL is downloaded, authenticated and
    // indexed, and the index is cached for all certificates of the issuer.
    async function checkByCrl(source, point) {
        let list, key, bytes;
        const fetchedAt = Date.now();
        if (forcedCrl !== undefined) {
            bytes = forcedCrl;
        } else {
            try {
                const url = networkUrl(source);
                key = issuerId + ':' + url.href;
                list = cache.get(key, ...limits, Date.now(), debug);
                // A CRL cached under a higher limit must not bypass this one.
                if (list && (list.size > options.policy.maxCrlBytes)) {
                    debug?.('CRL cache entry not used', { source: debugUrl(url), reason: 'exceeds maxCrlBytes',
                                                          bytes: list.size, maxCrlBytes: options.policy.maxCrlBytes });
                    list = undefined;
                }
                if (! list) {
                    bytes = await downloadCrl(url, signal, debug, options.policy.maxCrlBytes);
                }
            } catch (cause) {
                signal?.throwIfAborted();
                unreachable(source, cause);
                return undefined;
            }
        }
        let result;
        try {
            if (! list) {
                const label = (source === undefined) ? 'trFetchCrlOverride' : debugUrl(source);
                const parsed = parseCrl(bytes, options.policy.maxCrlBytes);
                debug?.('CRL parsed', { source: label, revokedEntries: parsed.revokedCount });
                list = await authenticateCrl(parsed, issuer);
                debug?.('CRL authenticated and indexed', { source: label, serials: list.serials.count,
                                                           indexBytes: list.serials.bytes });
            }
            result = await checkRevocationList(list, certificate, issuer, point.urls);
        } catch (cause) {
            invalid(source, cause);
            return undefined;
        }
        if ((key !== undefined) && (bytes !== undefined)) {
            cache.set(key, list, result.nextUpdate, fetchedAt, ...limits, Date.now(), debug);
        }
        return result;
    }

    // crlCacheScope 'certificate': the CRL is streamed and never held; only
    // whether it lists this certificate is cached. Cached certificates of the
    // same issuer and CRL URL are checked in the same pass and refreshed.
    async function checkByCertificate(source, point) {
        const fetchedAt = Date.now();
        let url;
        try {
            url = networkUrl(source);
        } catch (cause) {
            unreachable(source, cause);
            return undefined;
        }
        const group = issuerId + ':' + url.href;
        const key = issuerId + ':' + certificateId + ':' + url.href;
        const cached = resultCache.lookup(key, ...resultLimits, options.policy.maxCrlBytes, Date.now(), debug);
        if (cached) {
            return { revoked: cached.listed, nextUpdate: cached.nextUpdate };
        }
        const serial = Buffer.from(certificate.serialNumber.valueBlock.valueHexView);
        const candidates = resultCache.candidates(group, key, ...resultLimits);
        const serials = [ serial, ...candidates.map(([, entry]) => entry.serial) ];
        let streamed;
        try {
            streamed = await downloadCrl(url, signal, debug, options.policy.maxCrlBytes,
                                         chunks => authenticateCrlStream(chunks, issuer, options.policy.maxCrlBytes, serials));
        } catch (cause) {
            signal?.throwIfAborted();
            if (cause.invalidCrl) {
                invalid(source, cause);
            } else {
                unreachable(source, cause);
            }
            return undefined;
        }
        const { details, listed } = streamed;
        const isListed = bytes => listed.has(bytes.toString('latin1'));
        debug?.('CRL authenticated while streaming', { source: debugUrl(url), revokedEntries: streamed.revokedCount,
                                                       serialsChecked: serials.length, bytes: streamed.size });
        const common = { thisUpdate: details.thisUpdate, nextUpdate: details.nextUpdate, fetchedAt, size: streamed.size };
        // Refresh the other certificates from the same authenticated CRL,
        // unless it is not currently valid. Their issuer and issuance were
        // checked when first stored; the CRL's scope is checked again.
        let current = true;
        try {
            checkDates(details.thisUpdate, details.nextUpdate, Date.now());
        } catch (_) {
            current = false;
        }
        for (const [otherKey, entry] of current ? candidates : []) {
            try {
                checkScope(details.scope, entry.isCA, entry.urls);
            } catch (cause) {
                resultCache.remove(otherKey, debug, cause.message);
                continue;
            }
            const { expiresAt, lastUsedAt, ...facts } = entry;
            void expiresAt;
            void lastUsedAt;
            resultCache.store(otherKey, { ...facts, ...common, listed: isListed(entry.serial) }, ...resultLimits, Date.now(), debug, false);
        }
        let result;
        try {
            await checkCertificateAgainst(details, certificate, issuer, point.urls);
            result = { revoked: isListed(serial), nextUpdate: details.nextUpdate };
            checkDates(details.thisUpdate, details.nextUpdate, Date.now());
        } catch (cause) {
            invalid(source, cause);
            return undefined;
        }
        resultCache.store(key, { issuerId, certificateId, url: url.href, group, serial, isCA: isCaCertificate(certificate),
                                 urls: [ ...point.urls ], listed: result.revoked, ...common }, ...resultLimits, Date.now(), debug, true);
        return result;
    }

    const failures = [];
    let attempts = 0;
    for (const point of points) {
        if (point.unsupported) {
            failures.push(issue('invalidCrl', 'Reason-limited or indirect CRL distribution points are unsupported'));
            continue;
        }
        const sources = (forcedCrl !== undefined) ? [ undefined ] : point.urls;
        if (! sources.length) {
            failures.push(issue('unreachableCrlDistributionPoint', 'CRL distribution point has no fetchable HTTP(S) URI'));
        }
        for (const source of sources) {
            signal?.throwIfAborted();
            if (++attempts > 32) {
                failures.push(issue('unreachableCrlDistributionPoint', 'CRL distribution point lookup limit (32) exceeded'));
                break;
            }
            const byCertificate = (forcedCrl === undefined) && (options.policy.crlCacheScope === 'certificate');
            const result = byCertificate ? await checkByCertificate(source, point) : await checkByCrl(source, point);
            if (result === undefined) {
                continue;
            }
            debug?.('CRL serial lookup completed', { source: (source === undefined) ? 'trFetchCrlOverride' : debugUrl(source),
                                                     result: result.revoked ? 'revoked' : 'not listed', authenticated: true,
                                                     policy: 'revokedCertificate', configuredAction: options.policy.revokedCertificate,
                                                     action: result.revoked ? options.policy.revokedCertificate : 'continue', nextUpdate: result.nextUpdate });
            if (result.revoked) {
                applyPolicy(options.policy, issue('revokedCertificate', `Revoked ${certificateType} certificate: serial number is listed in the authenticated CRL`, undefined, source), debug, options.warningCb);
            }
            return result.nextUpdate;
        }
        if (attempts > 32) {
            break;
        }
    }
    for (const failure of failures) {
        applyPolicy(options.policy, failure, debug, options.warningCb);
    }
}

async function checkChain(peer, hostname, options, signal) {
    const debug = options.debug;
    debug?.('TLS verified; starting revocation checks', { hostname });
    const crlDepth = options.policy.disabled ? -1 : options.policy.crlCheckDepth;
    const ocspDepth = options.ocspPolicy.disabled ? -1 : options.ocspPolicy.ocspCheckDepth;
    const maxDepth = Math.max(crlDepth, ocspDepth);
    if (maxDepth < 0) {
        return;
    }
    const chainError = (message) => (crlDepth >= 0) ?
          new TrFetchCrlError('invalidCrl', message, { hostname }) :
          new TrFetchOcspError('rejectedCertificate', message, { hostname, ocspStatus: 'invalid-response' });
    if (! peer?.raw) {
        throw chainError('TLS connection did not expose a peer certificate');
    }
    const seen = new Set();
    let nextUpdate = Infinity;
    let ocspNextUpdate = Infinity;
    for (let depth = 0; peer; depth++) {
        if (depth > maxDepth) {
            break;
        }
        signal?.throwIfAborted();
        const fingerprint = peer.raw.toString('base64');
        if ((depth >= 32) || seen.has(fingerprint)) {
            throw chainError('Invalid or excessively long TLS certificate chain');
        }
        seen.add(fingerprint);
        const issuer = peer.issuerCertificate;
        const terminal = ! issuer?.raw || peer.raw.equals(issuer.raw);
        if ((depth > 0) && terminal) {
            debug?.('Trust anchor excluded from revocation checks', { hostname, depth, serial: peer.serialNumber });
            break;
        }
        const certificateDebug = debug ? (event, details) => debug(event, {
            hostname, certificate: (depth === 0) ? 'leaf' : 'intermediate CA', depth, serial: peer.serialNumber, ...details
        }) : undefined;
        if (depth <= crlDepth) {
            certificateDebug?.('CRL check started');
            const expires = await checkCertificate(peer, hostname, options, signal, depth === 0, certificateDebug);
            nextUpdate = Math.min(nextUpdate, expires ?? Infinity);
        } else {
            certificateDebug?.('CRL check skipped', { reason: options.policy.disabled ? 'disabled' : 'beyond configured depth' });
        }
        if (depth <= ocspDepth) {
            certificateDebug?.('OCSP check started');
            const expires = await checkOcspCertificate(peer, hostname, options, signal, depth === 0, certificateDebug);
            ocspNextUpdate = Math.min(ocspNextUpdate, expires ?? Infinity);
        } else {
            certificateDebug?.('OCSP check skipped', { reason: options.ocspPolicy.disabled ? 'disabled' : 'beyond configured depth' });
        }
        if (terminal) {
            break;
        }
        peer = issuer;
    }
    if (Date.now() >= nextUpdate) {
        applyPolicy(options.policy, new TrFetchCrlError('invalidCrl', 'CRL expired while checking the certificate chain', { hostname }), debug, options.warningCb);
    }
    if (Date.now() >= ocspNextUpdate) {
        applyPolicy(options.ocspPolicy, new TrFetchOcspError('rejectedCertificate',
                                                             'OCSP response expired while checking the certificate chain', { hostname, ocspStatus: 'invalid-response' }), debug, options.warningCb);
    }
    debug?.('Revocation checks completed; connection allowed', { hostname });
}

module.exports = { checkChain };
