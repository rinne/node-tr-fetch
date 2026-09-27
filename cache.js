'use strict';

const { debugUrl } = require('./debug');

function cacheEntry(key) {
    const separator = key.indexOf(':');
    return { issuer: key.slice(0, separator), source: debugUrl(key.slice(separator + 1)) };
}

// Cache authenticated revocation lists (see RevocationList in crl.js), never
// a policy decision, a failed lookup or the CRL bytes. A caller's shorter TTL
// also applies to entries populated by an earlier caller.
class CrlCache {
    #entries = new Map();

    prune(size, now = Date.now(), debug) {
        for (const [key, entry] of this.#entries) {
            if (now >= entry.expiresAt) {
                this.#entries.delete(key);
                debug?.('CRL cache expired', { ...cacheEntry(key),
                                               reason: (entry.expiresAt === entry.nextUpdate) ? 'CRL nextUpdate' : 'TTL', expiresAt: entry.expiresAt });
            }
        }
        while (this.#entries.size > Math.max(0, size)) {
            const key = this.#entries.keys().next().value;
            this.#entries.delete(key);
            debug?.('CRL cache purged', { ...cacheEntry(key), reason: (size <= 0) ? 'cache disabled' : 'LRU capacity', size });
        }
    }

    get(key, size, ttl, now = Date.now(), debug) {
        this.prune(size, now, debug);
        if ((size <= 0) || (ttl === 0)) {
            debug?.('CRL cache bypassed', { ...cacheEntry(key), reason: 'cache disabled', size, ttl });
            return undefined;
        }
        const entry = this.#entries.get(key);
        if (! entry) {
            debug?.('CRL cache miss', cacheEntry(key));
            return undefined;
        }
        if ((ttl !== -1) && ((now - entry.fetchedAt) >= (ttl * 1000))) {
            this.#entries.delete(key);
            debug?.('CRL cache expired', { ...cacheEntry(key), reason: 'caller TTL', ttl, ageSeconds: (now - entry.fetchedAt) / 1000 });
            return undefined;
        }
        this.#entries.delete(key);
        this.#entries.set(key, entry);
        debug?.('CRL cache hit', { ...cacheEntry(key), ageSeconds: (now - entry.fetchedAt) / 1000, expiresAt: entry.expiresAt });
        return entry.value;
    }

    set(key, value, nextUpdate, fetchedAt, size, ttl, now = Date.now(), debug) {
        this.prune(size, now, debug);
        if ((size <= 0) || (ttl === 0)) {
            debug?.('CRL cache store skipped', { ...cacheEntry(key), reason: 'cache disabled', size, ttl });
            return;
        }
        const expiresAt = Math.min(nextUpdate, (ttl === -1) ? Infinity : fetchedAt + (ttl * 1000));
        if (expiresAt <= now) {
            debug?.('CRL cache store skipped', { ...cacheEntry(key), reason: 'already expired', expiresAt });
            return;
        }
        this.#entries.delete(key);
        this.#entries.set(key, { value, fetchedAt, expiresAt, nextUpdate });
        debug?.('CRL cache stored', { ...cacheEntry(key), expiresAt, nextUpdate, ttl, size });
        this.prune(size, now, debug);
    }
}

// A stale entry is kept as a refresh candidate for this long after its last
// use, unless evicted earlier by the size limit.
const STALE_CANDIDATE_LIFETIME = 24 * 60 * 60 * 1000;

function resultEntry(entry) {
    return { issuer: entry.issuerId, certificate: entry.certificateId.slice(0, 16), source: debugUrl(entry.url) };
}

// Per-certificate results for crlCacheScope 'certificate': whether an
// authenticated CRL lists a certificate, until the earlier of the CRL's
// nextUpdate and the TTL. An expired entry is never used as an answer, but
// stays as a candidate: when the CRL is downloaded for any certificate, all
// cached certificates of the same issuer and CRL URL are checked in the same
// pass. A result from an older CRL never replaces one from a newer CRL. Only
// real lookups count as use for LRU order and staleness; refreshes do not.
class CrlResultCache {
    #entries = new Map();

    prune(size, now = Date.now(), debug) {
        for (const [key, entry] of this.#entries) {
            if ((now >= entry.expiresAt) && ((now - entry.lastUsedAt) > STALE_CANDIDATE_LIFETIME)) {
                this.#entries.delete(key);
                debug?.('CRL result cache candidate dropped', { ...resultEntry(entry), reason: 'unused' });
            }
        }
        while (this.#entries.size > Math.max(0, size)) {
            const [key, entry] = this.#entries.entries().next().value;
            this.#entries.delete(key);
            debug?.('CRL result cache purged', { ...resultEntry(entry), reason: (size <= 0) ? 'cache disabled' : 'LRU capacity', size });
        }
    }

    // The result for key if it can be used now, else undefined. A lookup is a
    // use: it keeps the entry, fresh or stale, as a refresh candidate.
    lookup(key, size, ttl, maxBytes, now = Date.now(), debug) {
        this.prune(size, now, debug);
        if ((size <= 0) || (ttl === 0)) {
            debug?.('CRL result cache bypassed', { reason: 'cache disabled', size, ttl });
            return undefined;
        }
        const entry = this.#entries.get(key);
        if (! entry) {
            debug?.('CRL result cache miss', {});
            return undefined;
        }
        entry.lastUsedAt = now;
        this.#entries.delete(key);
        this.#entries.set(key, entry);
        let stale;
        if (now >= entry.expiresAt) {
            stale = (entry.expiresAt === entry.nextUpdate) ? 'CRL nextUpdate' : 'TTL';
        } else if ((ttl !== -1) && ((now - entry.fetchedAt) >= (ttl * 1000))) {
            stale = 'caller TTL';
        } else if (entry.size > maxBytes) {
            stale = 'exceeds maxCrlBytes';
        }
        if (stale) {
            debug?.('CRL result cache stale', { ...resultEntry(entry), reason: stale });
            return undefined;
        }
        debug?.('CRL result cache hit', { ...resultEntry(entry), listed: entry.listed, ageSeconds: (now - entry.fetchedAt) / 1000,
                                          expiresAt: entry.expiresAt });
        return entry;
    }

    // Entries of the same issuer and CRL URL other than key, fresh or stale.
    candidates(group, key, size, ttl) {
        if ((size <= 0) || (ttl === 0)) {
            return [];
        }
        return [ ...this.#entries ].filter(([other, entry]) => (entry.group === group) && (other !== key));
    }

    // Store a result from an authenticated CRL: for the checked certificate
    // when used is true, otherwise as a refresh. Returns whether it was stored.
    store(key, fields, size, ttl, now = Date.now(), debug, used = true) {
        this.prune(size, now, debug);
        if ((size <= 0) || (ttl === 0)) {
            debug?.('CRL result cache store skipped', { ...resultEntry(fields), reason: 'cache disabled', size, ttl });
            return false;
        }
        const existing = this.#entries.get(key);
        if (existing && (existing.thisUpdate > fields.thisUpdate)) {
            debug?.('CRL result cache store skipped', { ...resultEntry(fields), reason: 'a newer CRL result is cached' });
            return false;
        }
        const expiresAt = Math.min(fields.nextUpdate, (ttl === -1) ? Infinity : fields.fetchedAt + (ttl * 1000));
        if (expiresAt <= now) {
            debug?.('CRL result cache store skipped', { ...resultEntry(fields), reason: 'already expired', expiresAt });
            return false;
        }
        const entry = { ...fields, expiresAt, lastUsedAt: used ? now : (existing?.lastUsedAt ?? now) };
        if (used || ! existing) {
            this.#entries.delete(key);
        }
        this.#entries.set(key, entry);
        debug?.(used ? 'CRL result cache stored' : 'CRL result cache refreshed', { ...resultEntry(entry), listed: entry.listed,
                                                                                    expiresAt, ttl, size });
        this.prune(size, now, debug);
        return true;
    }

    remove(key, debug, reason) {
        const entry = this.#entries.get(key);
        if (entry) {
            this.#entries.delete(key);
            debug?.('CRL result cache candidate dropped', { ...resultEntry(entry), reason });
        }
    }
}

module.exports = CrlCache;
module.exports.CrlResultCache = CrlResultCache;
module.exports.STALE_CANDIDATE_LIFETIME = STALE_CANDIDATE_LIFETIME;
