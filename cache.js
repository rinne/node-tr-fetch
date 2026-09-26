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

module.exports = CrlCache;
