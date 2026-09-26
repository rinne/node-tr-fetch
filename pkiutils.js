'use strict';

const asn1 = require('asn1js');
const pki = require('pkijs');
const { webcrypto } = require('node:crypto');

const cryptoEngine = new pki.CryptoEngine({ name: 'tr-fetch', crypto: webcrypto });

function parseDer(bytes, Type) {
    const decoded = asn1.fromBER(bytes);
    if ((decoded.offset !== bytes.length) || decoded.result.error) {
        throw new Error('Malformed ASN.1 data or trailing bytes');
    }
    return new Type({ schema: decoded.result });
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

module.exports = { cryptoEngine, parseDer, extensionsById, extensionValue, parseCertificate };
