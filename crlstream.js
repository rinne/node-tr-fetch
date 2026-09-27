'use strict';

// Check certificate serials against a CRL while it downloads. Only a small
// carry buffer of the CRL is held at any time: the signature is computed
// incrementally over the TBS bytes, and each revoked entry is checked and
// matched against the wanted serials as it arrives. Nothing is reported
// until the whole CRL has been read and authenticated.

const { createVerify } = require('node:crypto');
const asn1 = require('asn1js');
const pki = require('pkijs');
const { cryptoEngine } = require('./pkiutils');
const { isPem, decodePem, buildCrlStub, readEntry, scratch, checkCrlHeader, signatureOptions, nodeHash,
    certificateDer } = require('./crl');
const { buildSerialIndex } = require('./serials');

// Header fields, CRL extensions and the signature are small; entries more so.
const MAX_ELEMENT = 1024 * 1024;
const MAX_ENTRY = 64 * 1024;

// Errors in transferring the CRL, as opposed to errors in its content.
function transportError(error) {
    error.transport = true;
    return error;
}

// Count received bytes against the limit; mark failures as transport errors.
async function* limited(chunks, maxBytes, counter) {
    const iterator = chunks[Symbol.asyncIterator]();
    try {
        for (;;) {
            let step;
            try {
                step = await iterator.next();
            } catch (error) {
                throw transportError(error);
            }
            if (step.done) {
                return;
            }
            const chunk = Buffer.from(step.value.buffer, step.value.byteOffset, step.value.byteLength);
            counter.received += chunk.length;
            if (counter.received > maxBytes) {
                throw transportError(new Error(`CRL download exceeds maxCrlBytes (${maxBytes} bytes)`));
            }
            yield chunk;
        }
    } finally {
        await iterator.return?.();
    }
}

// Yield DER bytes. A PEM CRL (rare, and usually small) is collected within
// the size limit and decoded as strictly as in parseCrl.
async function* derChunks(chunks) {
    const iterator = chunks[Symbol.asyncIterator]();
    try {
        const first = [];
        let step;
        let length = 0;
        // Decide as parseCrl does, from the first 32 bytes.
        do {
            step = await iterator.next();
            if (! step.done) {
                first.push(step.value);
                length += step.value.length;
            }
        } while (! step.done && (length < 32));
        if (isPem(Buffer.concat(first))) {
            while (! step.done) {
                step = await iterator.next();
                if (! step.done) {
                    first.push(step.value);
                }
            }
            yield decodePem(Buffer.concat(first));
            return;
        }
        yield* first;
        while (! step.done) {
            step = await iterator.next();
            if (! step.done) {
                yield step.value;
            }
        }
    } finally {
        await iterator.return?.();
    }
}

// A reader over DER chunks that makes elements contiguous when they straddle
// chunk boundaries; only the straddling part is copied.
class DerReader {
    constructor(chunks, onChunk) {
        this.iterator = chunks[Symbol.asyncIterator]();
        this.onChunk = onChunk;
        this.buffer = Buffer.alloc(0);
        this.position = 0;
        this.consumed = 0;
        this.pulled = 0;
    }

    get available() {
        return this.buffer.length - this.position;
    }

    async pull() {
        const step = await this.iterator.next();
        if (step.done) {
            return false;
        }
        this.onChunk(step.value, this.pulled);
        this.pulled += step.value.length;
        this.buffer = this.available ? Buffer.concat([ this.buffer.subarray(this.position), step.value ]) : step.value;
        this.position = 0;
        return true;
    }

    async ensure(count) {
        while (this.available < count) {
            if (! await this.pull()) {
                throw new Error('Malformed ASN.1 data: truncated CRL');
            }
        }
    }

    // Header of the element at the current position, without consuming it:
    // { tag, headerLength, size } or undefined if not yet available.
    peek() {
        const bytes = this.buffer;
        const at = this.position;
        if (this.available < 2) {
            return undefined;
        }
        const first = bytes[at + 1];
        const count = (first & 0x80) ? (first & 0x7f) : 0;
        if (((first & 0x80) && ! count) || (count > 4) || ((bytes[at] & 0x1f) === 0x1f)) {
            throw new Error('Malformed ASN.1 data: unsupported tag or length encoding');
        }
        if (this.available < (2 + count)) {
            return undefined;
        }
        let length = count ? 0 : first;
        for (let i = 0; i < count; i++) {
            length = (length * 256) + bytes[at + 2 + i];
        }
        return { tag: bytes[at], headerLength: 2 + count, size: 2 + count + length };
    }

    async header() {
        for (;;) {
            const header = this.peek();
            if (header) {
                return header;
            }
            if (! await this.pull()) {
                throw new Error('Malformed ASN.1 data: truncated CRL');
            }
        }
    }

    skip(count) {
        this.position += count;
        this.consumed += count;
    }

    // A whole small element as its own buffer.
    async element() {
        const { tag, size } = await this.header();
        if (size > MAX_ELEMENT) {
            throw new Error('CRL element exceeds the size limit for its kind');
        }
        await this.ensure(size);
        const bytes = Buffer.from(this.buffer.subarray(this.position, this.position + size));
        this.skip(size);
        return { tag, bytes };
    }
}

// Read and authenticate a CRL from chunks (an async iterable of bytes),
// checking the given serials (Buffers). Returns the header details for
// certificate checks, the set of wanted serials that are listed (as latin1
// strings of their bytes), the entry count and the bytes received. Errors in
// the content are marked invalidCrl; transfer errors are marked transport.
async function authenticateCrlStream(chunks, issuer, maxBytes, serials) {
    const counter = { received: 0 };
    try {
        return await authenticate(chunks, issuer, maxBytes, serials, counter);
    } catch (error) {
        if (! error.transport) {
            error.invalidCrl = true;
        }
        throw error;
    }
}

async function authenticate(chunks, issuer, maxBytes, serials, counter) {
    const wanted = Buffer.concat(serials);
    const probes = buildSerialIndex(wanted, function(visit) {
        let offset = 0;
        for (const serial of serials) {
            visit(offset, offset + serial.length);
            offset += serial.length;
        }
    });
    let tbsStart = Infinity;
    let tbsEnd = Infinity;
    let verifier;
    const unfed = [];
    function feed(chunk, offset) {
        const from = Math.max(tbsStart, offset);
        const to = Math.min(tbsEnd, offset + chunk.length);
        if (from < to) {
            verifier.update(chunk.subarray(from - offset, to - offset));
        }
    }
    const reader = new DerReader(derChunks(limited(chunks, maxBytes, counter)), function(chunk, offset) {
        if (verifier) {
            feed(chunk, offset);
        } else {
            unfed.push([ chunk, offset ]);
        }
    });
    try {
        const outer = await reader.header();
        if (outer.tag !== 0x30) {
            throw new Error('Malformed CRL structure');
        }
        const outerEnd = outer.size;
        reader.skip(outer.headerLength);
        const tbs = await reader.header();
        if (tbs.tag !== 0x30) {
            throw new Error('Malformed CRL structure');
        }
        tbsStart = reader.consumed;
        tbsEnd = tbsStart + tbs.size;
        reader.skip(tbs.headerLength);
        // version, signature, issuer, thisUpdate, nextUpdate, entries, extensions
        const fields = [];
        let hash;
        let afterTime = false;
        let revokedCount = 0;
        let entryProblem;
        const listed = new Set();
        const s = scratch();
        while (reader.consumed < tbsEnd) {
            const next = await reader.header();
            if ((next.tag === 0x30) && afterTime) {
                // The revoked entries: checked one at a time, never kept.
                afterTime = false;
                reader.skip(next.headerLength);
                const listEnd = reader.consumed + next.size - next.headerLength;
                while (reader.consumed < listEnd) {
                    const entry = reader.peek();
                    if (entry && (entry.size > MAX_ENTRY)) {
                        throw new Error('Revoked certificate entry exceeds the size limit');
                    }
                    if (! entry || (reader.available < entry.size)) {
                        await reader.ensure(entry ? entry.size : (reader.available + 1));
                        continue;
                    }
                    if ((reader.consumed + entry.size) > listEnd) {
                        throw new Error('Malformed revoked certificate entry');
                    }
                    const at = reader.position;
                    entryProblem ??= readEntry(reader.buffer, at, at + entry.size, s, true).problem;
                    if (probes.hasRange(reader.buffer, s.number.start, s.number.end)) {
                        listed.add(reader.buffer.toString('latin1', s.number.start, s.number.end));
                    }
                    revokedCount++;
                    reader.skip(entry.size);
                }
                continue;
            }
            const element = await reader.element();
            fields.push(element.bytes);
            afterTime = (element.tag === 0x17) || (element.tag === 0x18);
            if ((element.tag === 0x30) && (hash === undefined)) {
                // The TBS signature algorithm chooses the digest before the
                // entries arrive; it must agree with the outer one at the end.
                const decoded = asn1.fromBER(element.bytes);
                if (decoded.result.error) {
                    throw new Error(`Malformed ASN.1 data: ${decoded.result.error}`);
                }
                const algorithm = new pki.AlgorithmIdentifier({ schema: decoded.result });
                hash = await cryptoEngine.getHashAlgorithm(algorithm);
                if (! [ 'SHA-256', 'SHA-384', 'SHA-512' ].includes(hash)) {
                    throw new Error(`Unsupported or weak CRL signature algorithm: ${algorithm.algorithmId}`);
                }
                verifier = createVerify(nodeHash(hash));
                for (const [chunk, offset] of unfed.splice(0)) {
                    feed(chunk, offset);
                }
            }
        }
        if ((reader.consumed !== tbsEnd) || (verifier === undefined)) {
            throw new Error('Malformed CRL structure');
        }
        const signatureAlgorithm = await reader.element();
        const signatureValue = await reader.element();
        if ((reader.consumed !== outerEnd) || reader.available || await reader.pull()) {
            throw new Error('Malformed ASN.1 data: trailing bytes');
        }
        const crl = buildCrlStub(fields, Buffer.concat([ signatureAlgorithm.bytes, signatureValue.bytes ]));
        const details = await checkCrlHeader(crl, issuer);
        if (details.hash !== hash) {
            throw new Error('CRL signature algorithm identifiers disagree');
        }
        const options = signatureOptions(crl, certificateDer(issuer));
        let valid = false;
        try {
            valid = (options !== undefined) && verifier.verify(options, crl.signatureValue.valueBlock.valueHexView);
        } catch (_) {
            valid = false;
        }
        if (! valid) {
            throw new Error('CRL signature verification failed');
        }
        if (entryProblem) {
            throw new Error(entryProblem);
        }
        return { details, listed, revokedCount, size: counter.received };
    } finally {
        await reader.iterator.return?.();
    }
}

module.exports = { authenticateCrlStream };
