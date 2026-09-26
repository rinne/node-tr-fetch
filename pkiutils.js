'use strict';

const asn1 = require('asn1js');
const pki = require('pkijs');
const { webcrypto } = require('node:crypto');

const cryptoEngine = new pki.CryptoEngine({ name: 'tr-fetch', crypto: webcrypto });

function parseDer(bytes, Type) {
    const decoded = asn1.fromBER(bytes);
    if (decoded.result.error) {
        throw new Error(`Malformed ASN.1 data: ${decoded.result.error}`);
    }
    if (decoded.offset !== bytes.length) {
        throw new Error('Malformed ASN.1 data: trailing bytes');
    }
    return new Type({ schema: decoded.result });
}

// A minimal DER element reader for data too large to decode into an object
// tree: single-byte tags and definite lengths only, always within bounds.
// derRead fills and returns a caller-supplied object, so loops over large
// CRLs create no garbage; derElement returns a new one.
function derElement(bytes, offset, end = bytes.length) {
    return derRead(bytes, offset, end, {});
}

function derRead(bytes, offset, end, element) {
    if ((offset + 2) > end) {
        throw new Error('Malformed ASN.1 data: truncated element');
    }
    const tag = bytes[offset];
    if ((tag & 0x1f) === 0x1f) {
        throw new Error('Malformed ASN.1 data: unsupported tag');
    }
    let start = offset + 2;
    let length = bytes[offset + 1];
    if (length & 0x80) {
        const count = length & 0x7f;
        if ((count === 0) || (count > 4) || ((start + count) > end)) {
            throw new Error('Malformed ASN.1 data: unsupported length encoding');
        }
        length = 0;
        for (let i = 0; i < count; i++) {
            length = (length * 256) + bytes[start + i];
        }
        start += count;
    }
    if ((start + length) > end) {
        throw new Error('Malformed ASN.1 data: element exceeds its container');
    }
    element.tag = tag;
    element.offset = offset;
    element.start = start;
    element.end = start + length;
    return element;
}

function derHeader(tag, length) {
    if (length < 0x80) {
        return Buffer.from([ tag, length ]);
    }
    const bytes = [];
    for (let value = length; value > 0; value = Math.floor(value / 256)) {
        bytes.unshift(value % 256);
    }
    return Buffer.from([ tag, 0x80 | bytes.length, ...bytes ]);
}

function oidString(bytes) {
    const parts = [];
    let value = 0;
    for (const byte of bytes) {
        value = (value * 128) + (byte & 0x7f);
        if (! (byte & 0x80)) {
            parts.push(value);
            value = 0;
        }
    }
    const first = parts.shift() ?? 0;
    const top = Math.min(2, Math.floor(first / 40));
    return [ top, first - (top * 40), ...parts ].join('.');
}

function extensionsById(extensions = []) {
    const result = new Map();
    for (const extension of extensions) {
        if (result.has(extension.extnID)) {
            throw new Error(`Duplicate extension ${extension.extnID}`);
        }
        result.set(extension.extnID, extension);
    }
    return result;
}

function extensionValue(extension, Type) {
    const data = extension.extnValue.valueBlock.valueHexView;
    const decoded = asn1.fromBER(data);
    if ((decoded.offset !== data.length) || decoded.result.error) {
        throw new Error(`Malformed extension ${extension.extnID}`);
    }
    if (Type) {
        return new Type({ schema: decoded.result });
    }
    return decoded.result;
}

function parseCertificate(bytes) {
    return parseDer(bytes, pki.Certificate);
}

module.exports = { cryptoEngine, parseDer, derElement, derRead, derHeader, oidString, extensionsById, extensionValue, parseCertificate };
