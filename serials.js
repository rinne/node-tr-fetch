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
        const group = this.#groups.get(serial.length);
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
                difference = data[base + i] - serial[i];
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

// LSD radix sort of record indices, one stable counting pass per byte
// position. The work is proportional to the total serial bytes, so no input
// can make it degrade. Positions where all records agree are skipped.
function sortRecords(data, width, count) {
    let order = new Uint32Array(count);
    let next = new Uint32Array(count);
    for (let i = 0; i < count; i++) {
        order[i] = i;
    }
    const buckets = new Uint32Array(257);
    for (let position = width - 1; (position >= 0) && (count > 1); position--) {
        buckets.fill(0);
        for (let i = 0; i < count; i++) {
            buckets[data[(order[i] * width) + position] + 1]++;
        }
        if (buckets.includes(count)) {
            continue;
        }
        for (let i = 1; i < 257; i++) {
            buckets[i] += buckets[i - 1];
        }
        for (let i = 0; i < count; i++) {
            next[buckets[data[(order[i] * width) + position]]++] = order[i];
        }
        [ order, next ] = [ next, order ];
    }
    // Own memory for a long-lived cache entry, not a slice of a shared pool.
    let sorted = Buffer.allocUnsafeSlow(width * count);
    let unique = 0;
    for (let i = 0; i < count; i++) {
        const from = order[i] * width;
        if ((unique > 0) && sameRecord(sorted, (unique - 1) * width, data, from, width)) {
            continue;
        }
        data.copy(sorted, unique * width, from, from + width);
        unique++;
    }
    if (unique < count) {
        const exact = Buffer.allocUnsafeSlow(width * unique);
        sorted.copy(exact, 0, 0, width * unique);
        sorted = exact;
    }
    return { width, count: unique, data: sorted };
}

// Build an index from forEachSerial(visit), which must call
// visit(bytes, start, end) for each serial. It is called twice: once to count
// serials of each length and once to copy them.
function buildSerialIndex(forEachSerial) {
    const counts = new Map();
    forEachSerial(function(bytes, start, end) {
        counts.set(end - start, (counts.get(end - start) ?? 0) + 1);
    });
    const unsorted = new Map();
    for (const [width, count] of counts) {
        unsorted.set(width, { data: Buffer.allocUnsafeSlow(width * count), count, filled: 0 });
    }
    forEachSerial(function(bytes, start, end) {
        const group = unsorted.get(end - start);
        if ((group === undefined) || (group.filled >= group.count)) {
            throw new Error('Serial enumeration changed between passes');
        }
        bytes.copy(group.data, group.filled * (end - start), start, end);
        group.filled++;
    });
    const groups = new Map();
    for (const [width] of counts) {
        const group = unsorted.get(width);
        if (group.filled !== group.count) {
            throw new Error('Serial enumeration changed between passes');
        }
        groups.set(width, sortRecords(group.data, width, group.count));
    }
    return new SerialIndex(groups);
}

module.exports = { SerialIndex, buildSerialIndex };
