'use strict';

// Revoked serial numbers as sorted, de-duplicated fixed-width records, one
// Buffer per serial length. Memory is the serial bytes themselves, outside
// the JS heap, and a lookup is a binary search among serials of the probe's
// length. Serials match only when their bytes are identical, as in DER.
class SerialIndex {
    #groups;
    #count;
    #bytes;

    constructor(groups) {
        this.#groups = groups;
        this.#count = 0;
        this.#bytes = 0;
        for (const group of groups.values()) {
            this.#count += group.count;
            this.#bytes += group.data.length;
        }
    }

    // Number of distinct serials.
    get count() {
        return this.#count;
    }

    // Bytes of serial data held.
    get bytes() {
        return this.#bytes;
    }

    has(serial) {
        return this.hasRange(serial, 0, serial.length);
    }

    // Whether bytes[start, end) is a listed serial, without copying it.
    hasRange(bytes, start, end) {
        const group = this.#groups.get(end - start);
        if (! group) {
            return false;
        }
        const { data, width } = group;
        let low = 0;
        let high = group.count - 1;
        while (low <= high) {
            const middle = (low + high) >>> 1;
            const base = middle * width;
            let difference = 0;
            for (let i = 0; (i < width) && ! difference; i++) {
                difference = data[base + i] - bytes[start + i];
            }
            if (! difference) {
                return true;
            }
            if (difference < 0) {
                low = middle + 1;
            } else {
                high = middle - 1;
            }
        }
        return false;
    }
}

function sameRecord(a, x, b, y, width) {
    for (let i = 0; i < width; i++) {
        if (a[x + i] !== b[y + i]) {
            return false;
        }
    }
    return true;
}

// LSD radix sort of serial positions in the source buffer, one stable
// counting pass per byte position, then a copy of each distinct serial into
// its own buffer. Sorting the positions avoids an unsorted copy of the
// serials. The work is proportional to the total serial bytes, so no input
// can make it degrade. Positions where all serials agree are skipped.
function sortRecords(bytes, positions, width) {
    const count = positions.length;
    let order = positions;
    let next = new positions.constructor(count);
    const buckets = new Uint32Array(257);
    for (let position = width - 1; (position >= 0) && (count > 1); position--) {
        buckets.fill(0);
        for (let i = 0; i < count; i++) {
            buckets[bytes[order[i] + position] + 1]++;
        }
        if (buckets.includes(count)) {
            continue;
        }
        for (let i = 1; i < 257; i++) {
            buckets[i] += buckets[i - 1];
        }
        for (let i = 0; i < count; i++) {
            next[buckets[bytes[order[i] + position]]++] = order[i];
        }
        [ order, next ] = [ next, order ];
    }
    next = undefined;
    let unique = 0;
    for (let i = 0; i < count; i++) {
        if ((i === 0) || ! sameRecord(bytes, order[i - 1], bytes, order[i], width)) {
            unique++;
        }
    }
    // Own memory for a long-lived cache entry, not a slice of a shared pool
    // or of the CRL.
    const sorted = Buffer.allocUnsafeSlow(width * unique);
    for (let i = 0, filled = 0; i < count; i++) {
        if ((i === 0) || ! sameRecord(bytes, order[i - 1], bytes, order[i], width)) {
            bytes.copy(sorted, filled * width, order[i], order[i] + width);
            filled++;
        }
    }
    return { width, count: unique, data: sorted };
}

// Build an index of serials in bytes. forEachSerial(visit) must call
// visit(start, end) for each serial; it is called twice, once to count the
// serials of each length and once to record where they are.
function buildSerialIndex(bytes, forEachSerial) {
    const counts = new Map();
    forEachSerial(function(start, end) {
        counts.set(end - start, (counts.get(end - start) ?? 0) + 1);
    });
    const Positions = (bytes.length <= 0xffffffff) ? Uint32Array : Float64Array;
    const located = new Map();
    for (const [width, count] of counts) {
        located.set(width, { positions: new Positions(count), filled: 0 });
    }
    forEachSerial(function(start, end) {
        const group = located.get(end - start);
        if ((group === undefined) || (group.filled >= group.positions.length)) {
            throw new Error('Serial enumeration changed between passes');
        }
        group.positions[group.filled++] = start;
    });
    const groups = new Map();
    for (const [width, group] of located) {
        if (group.filled !== group.positions.length) {
            throw new Error('Serial enumeration changed between passes');
        }
        groups.set(width, sortRecords(bytes, group.positions, width));
        located.set(width, undefined);
    }
    return new SerialIndex(groups);
}

module.exports = { SerialIndex, buildSerialIndex };
