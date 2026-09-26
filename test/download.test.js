'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const zlib = require('node:zlib');
const { randomBytes } = require('node:crypto');
const { once } = require('node:events');
const { downloadCrl } = require('../download');

let server, base;
const routes = new Map();

test.before(async function() {
    server = http.createServer(function(req, res) {
        const route = routes.get(req.url);
        if (route) {
            route(req, res);
        } else {
            res.writeHead(404).end();
        }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async function() {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
});

// Serve data in small writes, with or without Content-Length.
function serve(path, data, { length = true, chunk = 1000, encoding } = {}) {
    routes.set(path, function(req, res) {
        let body = data;
        if (encoding === 'gzip') {
            body = zlib.gzipSync(data);
            res.setHeader('content-encoding', 'gzip');
        }
        if (length) {
            res.setHeader('content-length', body.length);
        }
        for (let offset = 0; offset < body.length; offset += chunk) {
            res.write(body.subarray(offset, offset + chunk));
        }
        res.end();
    });
}

test('downloads arrive intact with and without Content-Length, and compressed', async function() {
    const data = randomBytes((3 * 1024 * 1024) + 17);
    serve('/length', data);
    serve('/chunked', data, { length: false });
    serve('/gzip', data, { encoding: 'gzip' });
    serve('/gzip-chunked', data, { encoding: 'gzip', length: false });
    serve('/empty', Buffer.alloc(0));
    serve('/empty-chunked', Buffer.alloc(0), { length: false });
    for (const path of [ '/length', '/chunked', '/gzip', '/gzip-chunked' ]) {
        const bytes = await downloadCrl(base + path, undefined, undefined, 16 * 1024 * 1024);
        assert.ok(bytes.equals(data), path);
        // Only received bytes are exposed.
        assert.equal(bytes.length, data.length, path);
    }
    for (const path of [ '/empty', '/empty-chunked' ]) {
        assert.equal((await downloadCrl(base + path, undefined, undefined, 1024)).length, 0, path);
    }
});

test('the size limit is exact for declared, chunked and compressed bodies', async function() {
    const data = randomBytes(200000);
    for (const [path, options] of [ [ '/limit-length', {} ], [ '/limit-chunked', { length: false } ],
        [ '/limit-gzip', { encoding: 'gzip' } ] ]) {
        serve(path, data, options);
        assert.ok((await downloadCrl(base + path, undefined, undefined, data.length)).equals(data), path);
        await assert.rejects(downloadCrl(base + path, undefined, undefined, data.length - 1),
            /CRL download exceeds maxCrlBytes \(199999 bytes\)/, path);
    }
});

test('a declared Content-Length above the limit fails before the body is read', async function() {
    let finished = false;
    routes.set('/huge', function(req, res) {
        res.writeHead(200, { 'content-length': 1024 * 1024 * 1024 });
        res.write(Buffer.alloc(1024));
        // The body would never complete; the download must not wait for it.
        res.on('close', () => {
            finished = true;
        });
    });
    const started = Date.now();
    await assert.rejects(downloadCrl(base + '/huge', undefined, undefined, 16 * 1024 * 1024), /exceeds maxCrlBytes/);
    assert.ok((Date.now() - started) < 5000);
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.equal(finished, true);
});

test('a body shorter or longer than its Content-Length fails', async function() {
    routes.set('/short', function(req, res) {
        res.writeHead(200, { 'content-length': 1000 });
        res.write(Buffer.alloc(10));
        setTimeout(() => res.destroy(), 20);
    });
    await assert.rejects(downloadCrl(base + '/short', undefined, undefined, 1024 * 1024));
    routes.set('/long', function(req, res) {
        // Bypass Node's own Content-Length enforcement on the raw socket.
        res.socket.end('HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\n' + 'x'.repeat(100));
    });
    const result = await downloadCrl(base + '/long', undefined, undefined, 1024 * 1024).then(x => x.length, () => 'rejected');
    // HTTP framing ends the body at Content-Length; extra bytes never reach it.
    assert.ok((result === 10) || (result === 'rejected'));
});
