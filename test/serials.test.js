'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSerialIndex } = require('../serials');

// Deterministic pseudo-random numbers, so failures can be reproduced.
function random(seed) {
    let state = seed >>> 0;
    return function() {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

// Serials placed at offsets inside one larger buffer, like entries in a CRL.
function indexFromShared(serials) {
    const bytes = Buffer.concat(serials.flatMap(serial => [ Buffer.from([ 0xee ]), serial ]));
    const ranges = [];
    let offset = 0;
    for (const serial of serials) {
        ranges.push([ offset + 1, offset + 1 + serial.length ]);
        offset += 1 + serial.length;
    }
    return { bytes, index: buildSerialIndex(bytes, visit => ranges.forEach(([start, end]) => visit(start, end))) };
}

function index(serials) {
    return indexFromShared(serials).index;
}

function variants(serial) {
    const result = [ Buffer.concat([ Buffer.from([ 0 ]), serial ]), Buffer.concat([ serial, Buffer.from([ 0 ]) ]) ];
    if (serial.length) {
        result.push(serial.subarray(1), serial.subarray(0, -1));
        for (const position of [ 0, serial.length >> 1, serial.length - 1 ]) {
            for (const delta of [ 1, 255 ]) {
                const changed = Buffer.from(serial);
                changed[position] = (changed[position] + delta) & 0xff;
                result.push(changed);
            }
        }
    }
    return result;
}

test('serials match only by identical bytes, including length and leading zeros', function() {
    const serials = [ [ 0x2a ], [ 0x00, 0xff ], [ 0xff ], [ 0x01 ], [ 0x00, 0x00, 0x01 ], [], [ 1, 2, 3 ] ].map(x => Buffer.from(x));
    const result = index(serials);
    for (const serial of serials) {
        assert.equal(result.has(serial), true, serial.toString('hex'));
    }
    for (const absent of [ [ 0x00, 0x2a ], [ 0x00, 0x01 ], [ 0xff, 0x00 ], [ 0x00 ], [ 0x2b ], [ 1, 2 ], [ 1, 2, 3, 0 ], [ 0, 1, 2, 3 ] ]) {
        assert.equal(result.has(Buffer.from(absent)), false, Buffer.from(absent).toString('hex'));
    }
});

test('an empty index finds nothing and holds no memory', function() {
    const result = index([]);
    assert.equal(result.count, 0);
    assert.equal(result.bytes, 0);
    for (const probe of [ [], [ 0 ], [ 0x2a ], Array(20).fill(0xff) ]) {
        assert.equal(result.has(Buffer.from(probe)), false);
    }
});

test('duplicates are stored once and memory is exactly the distinct serial bytes', function() {
    const serials = [ [ 1 ], [ 1 ], [ 2, 3 ], [ 2, 3 ], [ 2, 3 ], [ 4, 5, 6 ], [], [] ].map(x => Buffer.from(x));
    const result = index(serials);
    assert.equal(result.count, 4);
    assert.equal(result.bytes, 1 + 2 + 3 + 0);
    for (const serial of serials) {
        assert.equal(result.has(serial), true);
    }
});

test('the index copies serials and does not retain the source buffer', function() {
    const serials = Array.from({ length: 500 }, (_, i) => Buffer.from([ i >> 8, i & 0xff, 7 ]));
    const { bytes, index: result } = indexFromShared(serials);
    const probes = serials.map(serial => Buffer.from(serial));
    bytes.fill(0);
    for (const probe of probes) {
        assert.equal(result.has(probe), true);
    }
    assert.equal(result.bytes, 500 * 3);
});

test('random serial sets of mixed lengths agree with a reference set', function() {
    const widths = [ 0, 1, 2, 3, 4, 8, 15, 16, 17, 19, 20, 21, 32, 64, 255, 300 ];
    for (let seed = 1; seed <= 25; seed++) {
        const next = random(seed);
        const count = Math.floor(next() * 3000);
        const serials = [];
        for (let i = 0; i < count; i++) {
            const width = widths[Math.floor(next() * widths.length)];
            if ((next() < 0.1) && serials.length) {
                // Repeat an earlier serial.
                serials.push(serials[Math.floor(next() * serials.length)]);
                continue;
            }
            const serial = Buffer.alloc(width);
            // Mostly shared prefixes, so sorting must reach the last bytes.
            const shared = Math.floor(next() * width);
            for (let j = 0; j < width; j++) {
                serial[j] = (j < shared) ? ((seed * 31) + j) & 0xff : Math.floor(next() * 256);
            }
            serials.push(serial);
        }
        const reference = new Set(serials.map(serial => serial.toString('hex')));
        const { index: result } = indexFromShared(serials);
        assert.equal(result.count, reference.size, `seed ${seed}`);
        assert.equal(result.bytes, [ ...reference ].reduce((sum, hex) => sum + (hex.length / 2), 0), `seed ${seed}`);
        for (const serial of serials) {
            assert.equal(result.has(serial), true, `seed ${seed} ${serial.toString('hex')}`);
            for (const probe of variants(serial)) {
                assert.equal(result.has(probe), reference.has(probe.toString('hex')), `seed ${seed} probe ${probe.toString('hex')}`);
            }
        }
    }
});

test('records sharing all but the last byte, or differing only in the first, sort correctly', function() {
    const tail = Array.from({ length: 256 }, (_, i) => Buffer.concat([ Buffer.alloc(19, 0xab), Buffer.from([ 255 - i ]) ]));
    const head = Array.from({ length: 256 }, (_, i) => Buffer.concat([ Buffer.from([ i ]), Buffer.alloc(19, 0xcd) ]));
    const constant = Array.from({ length: 50 }, () => Buffer.alloc(16, 0x11));
    const result = index([ ...tail, ...head, ...constant ]);
    assert.equal(result.count, 256 + 256 + 1);
    for (const serial of [ ...tail, ...head, constant[0] ]) {
        assert.equal(result.has(serial), true);
    }
    assert.equal(result.has(Buffer.concat([ Buffer.alloc(19, 0xab), Buffer.from([ 0 ]) ])), true);
    assert.equal(result.has(Buffer.concat([ Buffer.alloc(18, 0xab), Buffer.from([ 0xac, 0 ]) ])), false);
    assert.equal(result.has(Buffer.alloc(16, 0x12)), false);
});

test('a large index of realistic 16-byte serials finds every member and no neighbours', function() {
    const next = random(0x5eed);
    const serials = Array.from({ length: 200000 }, function() {
        const serial = Buffer.alloc(16);
        for (let j = 0; j < 16; j++) {
            serial[j] = Math.floor(next() * 256);
        }
        serial[0] &= 0x7f;
        return serial;
    });
    const result = index(serials);
    const reference = new Set(serials.map(serial => serial.toString('hex')));
    assert.equal(result.count, reference.size);
    assert.equal(result.bytes, reference.size * 16);
    for (let i = 0; i < serials.length; i += 7) {
        assert.equal(result.has(serials[i]), true);
        const neighbour = Buffer.from(serials[i]);
        neighbour[15] ^= 1;
        assert.equal(result.has(neighbour), reference.has(neighbour.toString('hex')));
    }
});

test('an enumeration that changes between the two passes is rejected', function() {
    const bytes = Buffer.from([ 1, 2, 3 ]);
    let pass = 0;
    assert.throws(() => buildSerialIndex(bytes, function(visit) {
        pass++;
        visit(0, (pass === 1) ? 2 : 1);
    }), /changed between passes/);
    pass = 0;
    assert.throws(() => buildSerialIndex(bytes, function(visit) {
        pass++;
        visit(0, 1);
        if (pass === 2) {
            visit(1, 2);
        }
    }), /changed between passes/);
    pass = 0;
    assert.throws(() => buildSerialIndex(bytes, function(visit) {
        pass++;
        visit(0, 1);
        if (pass === 1) {
            visit(1, 2);
        }
    }), /changed between passes/);
});

test('the index owns its memory: no slice of the source buffer or of a shared pool', function() {
    const serials = [ [ 1 ], [ 2, 3 ], [ 4, 5, 6 ] ].map(x => Buffer.from(x));
    const { bytes, index: result } = indexFromShared(serials);
    // The private groups are not reachable; memory accounting and lookups
    // after the source is overwritten show that nothing refers back to it.
    bytes.fill(0xff);
    assert.equal(result.bytes, 6);
    for (const serial of serials) {
        assert.equal(result.has(serial), true);
    }
    assert.equal(result.has(Buffer.from([ 0xff ])), false);
});
