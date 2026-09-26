'use strict';

const { createHash } = require('node:crypto');
const { parseCertificate, distributionPoints, parseCrl, authenticateCrl, checkRevocationList } = require('./crl');
const { networkUrl, downloadCrl } = require('./download');
const { TrFetchCrlError, TrFetchOcspError, applyPolicy } = require('./errors');
const { checkOcspCertificate } = require('./ocsp');
const CrlCache = require('./cache');
const { debugUrl } = require('./debug');

const cache = new CrlCache();

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
        applyPolicy(options.policy, issue('invalidCrl', `Cannot read certificate CRL information: ${cause.message}`, cause), debug);
        return;
    }
    if (points === undefined) {
        applyPolicy(options.policy, issue('missingCrlDistributionPoint', 'Missing CRL distribution point'), debug);
        return;
    }
    let issuer;
    try {
        if (! peer.issuerCertificate?.raw) {
            throw new Error('The verified TLS chain does not expose the issuer certificate');
        }
        issuer = parseCertificate(peer.issuerCertificate.raw);
    } catch (cause) {
        applyPolicy(options.policy, issue('invalidCrl', `Cannot authenticate CRL: ${cause.message}`, cause), debug);
        return;
    }
    const issuerId = createHash('sha256').update(peer.issuerCertificate.raw).digest('hex');
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
            let list, key, bytes;
            const fetchedAt = Date.now();
            if (forcedCrl !== undefined) {
                bytes = forcedCrl;
            } else {
                try {
                    const url = networkUrl(source);
                    key = issuerId + ':' + url.href;
                    list = cache.get(key, options.cacheSize, options.cacheTTL, Date.now(), debug);
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
                    failures.push(issue('unreachableCrlDistributionPoint',
                                        `Unreachable CRL distribution point ${sourceLabel(source)}: ${cause.message}`, cause, source));
                    continue;
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
                failures.push(issue('invalidCrl',
                                    `Invalid CRL from ${(source === undefined) ? 'trFetchCrlOverride' : sourceLabel(source)}: ${cause.message}`, cause, source));
                continue;
            }
            if ((key !== undefined) && (bytes !== undefined)) {
                cache.set(key, list, result.nextUpdate, fetchedAt, options.cacheSize, options.cacheTTL, Date.now(), debug);
            }
            debug?.('CRL serial lookup completed', { source: (source === undefined) ? 'trFetchCrlOverride' : debugUrl(source),
                                                     result: result.revoked ? 'revoked' : 'not listed', authenticated: true,
                                                     policy: 'revokedCertificate', configuredAction: options.policy.revokedCertificate,
                                                     action: result.revoked ? options.policy.revokedCertificate : 'continue', nextUpdate: result.nextUpdate });
            if (result.revoked) {
                applyPolicy(options.policy, issue('revokedCertificate', `Revoked ${certificateType} certificate: serial number is listed in the authenticated CRL`, undefined, source), debug);
            }
            return result.nextUpdate;
        }
        if (attempts > 32) {
            break;
        }
    }
    for (const failure of failures) {
        applyPolicy(options.policy, failure, debug);
    }
}

async function checkChain(peer, hostname, options, signal) {
    const debug = options.debug;
    debug?.('TLS verified; starting revocation checks', { hostname });
    const crlDepth = options.policy.disabled ? -1 : options.checkDepth;
    const ocspDepth = options.ocspPolicy.disabled ? -1 : options.ocspCheckDepth;
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
        applyPolicy(options.policy, new TrFetchCrlError('invalidCrl', 'CRL expired while checking the certificate chain', { hostname }), debug);
    }
    if (Date.now() >= ocspNextUpdate) {
        applyPolicy(options.ocspPolicy, new TrFetchOcspError('rejectedCertificate',
                                                             'OCSP response expired while checking the certificate chain', { hostname, ocspStatus: 'invalid-response' }), debug);
    }
    debug?.('Revocation checks completed; connection allowed', { hostname });
}

module.exports = { checkChain };
