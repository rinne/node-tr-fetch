'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const { execFile } = require('node:child_process');
const { once } = require('node:events');
const fixtures = require('./fixtures');

const BIN = path.join(__dirname, '..', 'bin', 'tr-curl.js');

let tmp, ca, caFile, server, base, secure, secureUrl, revoked, revokedUrl, untrusted, untrustedUrl, bare, bareUrl;
const routes = new Map();

function curl(args, options = {}) {
    return new Promise(function(resolve) {
        const child = execFile(process.execPath, [ BIN, ...args ], { encoding: 'buffer', maxBuffer: 16 * 1024 * 1024, ...options },
                               function(error, stdout, stderr) {
                                   resolve({ code: error ? error.code : 0, stdout: stdout.toString(), stderr: stderr.toString(), raw: stdout });
                               });
        if (options.input !== undefined) {
            child.stdin.end(options.input);
        }
    });
}

async function listen(value) {
    value.listen(0, '127.0.0.1');
    await once(value, 'listening');
    return value.address().port;
}

async function echo(req, res) {
    const chunks = [];
    for await (const chunk of req) {
        chunks.push(chunk);
    }
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() }));
}

function ocspRoute(issuer, options) {
    return async function(req, res) {
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        res.setHeader('content-type', 'application/ocsp-response');
        res.end((await fixtures.ocsp(issuer, Buffer.concat(chunks), options)).der);
    };
}

async function httpsServer(leaf) {
    const value = https.createServer({ cert: leaf.pem, key: leaf.key }, (req, res) => res.end('secure'));
    return [ value, `https://localhost:${await listen(value)}/` ];
}

test.before(async function() {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tr-curl-'));
    server = http.createServer(function(req, res) {
        const route = routes.get(req.url.replace(/\?.*$/, '')) ?? echo;
        Promise.resolve(route(req, res)).catch(error => res.destroy(error));
    });
    base = `http://127.0.0.1:${await listen(server)}`;
    ca = await fixtures.certificate({ ca: true });
    caFile = path.join(tmp, 'ca.pem');
    fs.writeFileSync(caFile, ca.pem);
    routes.set('/crl', async (req, res) => res.end((await fixtures.crl(ca)).der));
    routes.set('/crl-revoked', async (req, res) => res.end((await fixtures.crl(ca, { serials: [ 43 ] })).der));
    routes.set('/ocsp', ocspRoute(ca));
    routes.set('/ocsp-revoked', ocspRoute(ca, { status: 'revoked' }));
    routes.set('/crl-42', async (req, res) => res.end((await fixtures.crl(ca, { serials: [ 42 ] })).der));
    [ secure, secureUrl ] = await httpsServer(await fixtures.certificate({ issuer: ca, serial: 42,
                                                                           urls: [ base + '/crl' ], ocspUrls: [ base + '/ocsp' ] }));
    [ revoked, revokedUrl ] = await httpsServer(await fixtures.certificate({ issuer: ca, serial: 43,
                                                                             urls: [ base + '/crl-revoked' ], ocspUrls: [ base + '/ocsp-revoked' ] }));
    [ untrusted, untrustedUrl ] = await httpsServer(await fixtures.certificate({ issuer: await fixtures.certificate({ ca: true, serial: 7 }) }));
    // Trusted, but with no CRL distribution point or OCSP responder.
    [ bare, bareUrl ] = await httpsServer(await fixtures.certificate({ issuer: ca, serial: 45 }));
    routes.set('/redirect', function(req, res) {
        res.writeHead(Number(new URL(req.url, base).searchParams.get('status') ?? 302), {
            location: new URL(req.url, base).searchParams.get('to') ?? '/echo'
        });
        res.end('moved');
    });
    routes.set('/loop', (req, res) => res.writeHead(302, { location: '/loop' }).end());
    routes.set('/missing', (req, res) => res.writeHead(404).end('not here'));
    routes.set('/big', (req, res) => res.end(Buffer.alloc(3 * 1024 * 1024, 'x')));
    routes.set('/binary', (req, res) => res.end(Buffer.from([ 0, 1, 2 ])));
    routes.set('/slow', (req, res) => setTimeout(() => res.end('late'), 2000).unref());
    routes.set('/partial', function(req, res) {
        res.writeHead(200, { 'content-length': 100 });
        res.write('short');
        setTimeout(() => res.destroy(), 50);
    });
});

test.after(async function() {
    for (const value of [ server, secure, revoked, untrusted, bare ]) {
        value.closeAllConnections();
        await new Promise(resolve => value.close(resolve));
    }
    fs.rmSync(tmp, { recursive: true, force: true });
});

test('help, version and usage errors', async function() {
    const help = await curl([ '--help' ]);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /^Usage: tr-curl/);
    assert.match(help.stdout, / -L, --location +Follow redirects/);
    assert.match(help.stdout, /--max-time <seconds>/);
    const version = await curl([ '-V' ]);
    assert.equal(version.code, 0);
    assert.match(version.stdout, /^tr-curl \d+\.\d+\.\d+ .*\nProtocols: http https\n/);
    for (const args of [ [ '--bogus', base ], [ '-m', 'soon', base ], [], [ '-f', '--fail-with-body', base ],
                         [ '-I', '-d', 'x', base ], [ '-o', 'a', '-O', base ], [ '--tr-fetch-options', '{"method":"PUT"}', base ], [ '--trfetch-options', '{}', base ] ]) {
        const result = await curl(args);
        assert.equal(result.code, 2, args.join(' '));
        assert.match(result.stderr, /^tr-curl: /);
    }
});

test('GET writes the body to stdout with curl-like default headers', async function() {
    const result = await curl([ '-s', `${base}/echo?a=1` ]);
    assert.equal(result.code, 0);
    const request = JSON.parse(result.stdout);
    assert.equal(request.method, 'GET');
    assert.equal(request.url, '/echo?a=1');
    assert.match(request.headers['user-agent'], /^tr-curl\//);
    assert.equal(request.headers.accept, '*/*');
    assert.equal(result.stderr, '');
});

test('data options, JSON, --get and custom headers', async function() {
    const bodyFile = path.join(tmp, 'body.txt');
    fs.writeFileSync(bodyFile, 'line1\r\nline2\n');
    let request = JSON.parse((await curl([ '-s', '-d', 'a=1', '-d', `@${bodyFile}`, '--data-raw', '@raw',
                                           '--data-urlencode', 'n=a b&c', '--data-binary', `@${bodyFile}`, base ])).stdout);
    assert.equal(request.method, 'POST');
    assert.equal(request.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.equal(request.body, 'a=1&line1line2&@raw&n=a%20b%26c&line1\r\nline2\n');
    request = JSON.parse((await curl([ '-s', '--json', '{"a":', '--json', '1}', base ])).stdout);
    assert.equal(request.body, '{"a":1}');
    assert.equal(request.headers['content-type'], 'application/json');
    assert.equal(request.headers.accept, 'application/json');
    request = JSON.parse((await curl([ '-s', '-d', '@-', base ], { input: 'from\nstdin' })).stdout);
    assert.equal(request.body, 'fromstdin');
    request = JSON.parse((await curl([ '-s', '-G', '-d', 'q=1', '-d', 'r=2', `${base}/echo?x=0` ])).stdout);
    assert.equal(request.method, 'GET');
    assert.equal(request.url, '/echo?x=0&q=1&r=2');
    const headerFile = path.join(tmp, 'headers.txt');
    fs.writeFileSync(headerFile, 'X-From-File: yes\n\nX-Second: 2\n');
    request = JSON.parse((await curl([ '-s', '-X', 'PATCH', '-H', 'X-Test: value', '-H', 'User-Agent:', '-H', 'X-Empty;',
                                       '-H', `@${headerFile}`, '-A', 'ignored', '-e', 'http://ref.example/', '-r', '0-9', base ])).stdout);
    assert.equal(request.method, 'PATCH');
    assert.equal(request.headers['x-test'], 'value');
    assert.equal(request.headers['x-empty'], '');
    assert.equal(request.headers['x-from-file'], 'yes');
    assert.equal(request.headers['x-second'], '2');
    assert.notEqual(request.headers['user-agent'], 'ignored');
    assert.equal(request.headers.referer, 'http://ref.example/');
    assert.equal(request.headers.range, 'bytes=0-9');
});

test('basic and bearer authentication, including URL credentials', async function() {
    let request = JSON.parse((await curl([ '-s', '-u', 'joe:secret:colon', base ])).stdout);
    assert.equal(request.headers.authorization, 'Basic ' + Buffer.from('joe:secret:colon').toString('base64'));
    request = JSON.parse((await curl([ '-s', base.replace('//', '//ann:p%40ss@') + '/echo' ])).stdout);
    assert.equal(request.headers.authorization, 'Basic ' + Buffer.from('ann:p@ss').toString('base64'));
    request = JSON.parse((await curl([ '-s', '--oauth2-bearer', 'token', base ])).stdout);
    assert.equal(request.headers.authorization, 'Bearer token');
});

test('redirects: following, limits, method changes and credential scope', async function() {
    const unfollowed = await curl([ '-s', `${base}/redirect` ]);
    assert.equal(unfollowed.stdout, 'moved');
    const other = base.replace('127.0.0.1', 'localhost');
    let request = JSON.parse((await curl([ '-s', '-L', '-u', 'joe:pw', '-H', 'Cookie: c=1', '-e', ';auto', '-d', 'x=1',
                                           `${base}/redirect?to=${encodeURIComponent(other + '/echo')}` ])).stdout);
    assert.equal(request.method, 'GET');
    assert.equal(request.body, '');
    assert.equal(request.headers.authorization, undefined);
    assert.equal(request.headers.cookie, undefined);
    assert.equal(request.headers.referer, `${base}/redirect?to=${encodeURIComponent(other + '/echo')}`);
    request = JSON.parse((await curl([ '-s', '--location-trusted', '-u', 'joe:pw', '-H', 'Cookie: c=1', '-d', 'x=1',
                                       `${base}/redirect?status=307&to=${encodeURIComponent(other + '/echo')}` ])).stdout);
    assert.equal(request.method, 'POST');
    assert.equal(request.body, 'x=1');
    assert.match(request.headers.authorization, /^Basic /);
    assert.equal(request.headers.cookie, 'c=1');
    request = JSON.parse((await curl([ '-s', '-L', '-u', 'joe:pw', `${base}/redirect?status=301` ])).stdout);
    assert.match(request.headers.authorization, /^Basic /);
    const loop = await curl([ '-sS', '-L', '--max-redirs', '2', `${base}/loop` ]);
    assert.equal(loop.code, 47);
    assert.match(loop.stderr, /Maximum \(2\) redirects followed/);
    const head = await curl([ '-s', '-I', '-L', `${base}/redirect` ]);
    assert.match(head.stdout, /^HTTP\/1\.1 302 Found\r\n(.+\r\n)*location: \/echo\r\n(.+\r\n)*\r\nHTTP\/1\.1 200 OK\r\n/);
    assert.doesNotMatch(head.stdout, /moved/);
    const unsupported = await curl([ '-sS', '-L', `${base}/redirect?to=${encodeURIComponent('ftp://example.com/')}` ]);
    assert.equal(unsupported.code, 1);
});

test('--include, --fail, --fail-with-body and --fail-early', async function() {
    const included = await curl([ '-s', '-i', `${base}/missing` ]);
    assert.equal(included.code, 0);
    assert.match(included.stdout, /^HTTP\/1\.1 404 Not Found\r\n(.+\r\n)+\r\nnot here$/);
    const failed = await curl([ '-sS', '-f', `${base}/missing` ]);
    assert.equal(failed.code, 22);
    assert.equal(failed.stdout, '');
    assert.match(failed.stderr, /^tr-curl: \(22\) The requested URL returned error: 404\n$/);
    assert.equal((await curl([ '-s', '-f', `${base}/missing` ])).stderr, '');
    const withBody = await curl([ '-s', '--fail-with-body', `${base}/missing` ]);
    assert.equal(withBody.code, 22);
    assert.equal(withBody.stdout, 'not here');
    const many = await curl([ '-s', '-f', `${base}/missing`, `${base}/echo` ]);
    assert.equal(many.code, 22);
    assert.match(many.stdout, /"method":"GET"/);
    const early = await curl([ '-s', '-f', '--fail-early', `${base}/missing`, `${base}/echo` ]);
    assert.equal(early.code, 22);
    assert.equal(early.stdout, '');
});

test('output files, --remote-name, --output-dir, --create-dirs and --remove-on-error', async function() {
    const dir = path.join(tmp, 'out');
    let result = await curl([ '-s', '--output-dir', dir, '--create-dirs', '-o', 'first.json', '-O',
                              `${base}/echo`, `${base}/big` ]);
    assert.equal(result.code, 2);
    result = await curl([ '-s', '--output-dir', dir, '--create-dirs', '-o', 'first.json', '-o', 'nested/second.txt',
                          `${base}/echo`, `${base}/missing`, `${base}/echo?third` ]);
    assert.equal(result.code, 0);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'first.json'))).url, '/echo');
    assert.equal(fs.readFileSync(path.join(dir, 'nested', 'second.txt'), 'utf8'), 'not here');
    assert.match(result.stdout, /"url":"\/echo\?third"/);
    result = await curl([ '-s', '--output-dir', dir, '--remote-name-all', `${base}/big`, `${base}/echo?q` ]);
    assert.equal(result.code, 0);
    assert.equal(fs.statSync(path.join(dir, 'big')).size, 3 * 1024 * 1024);
    assert.ok(fs.existsSync(path.join(dir, 'echo')));
    assert.equal((await curl([ '-s', '-O', `${base}/` ])).code, 23);
    const failed = path.join(dir, 'failed.txt');
    assert.equal((await curl([ '-s', '-f', '-o', failed, `${base}/missing` ])).code, 22);
    assert.ok(! fs.existsSync(failed));
    assert.equal((await curl([ '-s', '--fail-with-body', '-o', failed, `${base}/missing` ])).code, 22);
    assert.equal(fs.readFileSync(failed, 'utf8'), 'not here');
    assert.equal((await curl([ '-s', '--fail-with-body', '--remove-on-error', '-o', failed, `${base}/missing` ])).code, 22);
    assert.ok(! fs.existsSync(failed));
    const partial = path.join(dir, 'partial.txt');
    result = await curl([ '-sS', '--remove-on-error', '-o', partial, `${base}/partial` ]);
    assert.equal(result.code, 18);
    assert.match(result.stderr, /transfer closed with 95 bytes remaining to read/);
    assert.ok(! fs.existsSync(partial));
});

test('--etag-compare sends If-None-Match from a file', async function() {
    const file = path.join(tmp, 'etag');
    fs.writeFileSync(file, '"v1"\n');
    assert.equal(JSON.parse((await curl([ '-s', '--etag-compare', file, base ])).stdout).headers['if-none-match'], '"v1"');
    const missing = await curl([ '-s', '--etag-compare', path.join(tmp, 'no-etag'), base ]);
    assert.equal(JSON.parse(missing.stdout).headers['if-none-match'], '""');
    assert.match(missing.stderr, /Warning: Failed to open/);
});

test('size and time limits and network failures use curl exit codes', async function() {
    let result = await curl([ '-sS', '--max-filesize', '1M', `${base}/big` ]);
    assert.equal(result.code, 63);
    assert.equal(result.stdout, '');
    assert.equal((await curl([ '-s', '--max-filesize', '4M', '-o', path.join(tmp, 'ok'), `${base}/big` ])).code, 0);
    result = await curl([ '-sS', '-m', '0.3', `${base}/slow` ]);
    assert.equal(result.code, 28);
    assert.match(result.stderr, /Operation timed out after \d+ milliseconds with 0 bytes received/);
    const closed = http.createServer();
    const port = await listen(closed);
    await new Promise(resolve => closed.close(resolve));
    result = await curl([ '-sS', `http://127.0.0.1:${port}/` ]);
    assert.equal(result.code, 7);
    assert.match(result.stderr, /Failed to connect to 127\.0\.0\.1 port \d+/);
    result = await curl([ '-sS', 'http://host.invalid/' ]);
    assert.equal(result.code, 6);
    assert.equal((await curl([ '-sS', 'gopher://example.com/' ])).code, 1);
    assert.equal((await curl([ '-sS', 'http://[bad/' ])).code, 3);
});

test('progress meter and progress bar go to stderr unless silenced', async function() {
    const file = path.join(tmp, 'progress');
    let result = await curl([ '-o', file, `${base}/big` ]);
    assert.match(result.stderr, /% Total {4}% Received % Xferd {2}Average Speed/);
    assert.match(result.stderr, /\r100 3072k {2}100 3072k {4}0 {5}0 /);
    result = await curl([ '-#', '-o', file, `${base}/big` ]);
    assert.match(result.stderr, /#+ 100\.0%\n$/);
    for (const flag of [ '-s', '--no-progress-meter' ]) {
        assert.equal((await curl([ flag, '-o', file, `${base}/big` ])).stderr, '');
    }
});

test('HTTPS uses trFetch CRL and OCSP checks, with --cacert trust', async function() {
    let result = await curl([ '-s', '--cacert', caFile, secureUrl ]);
    assert.equal(result.code, 0);
    assert.equal(result.stdout, 'secure');
    result = await curl([ '-sS', secureUrl ]);
    assert.equal(result.code, 60);
    assert.match(result.stderr, /SSL certificate problem/);
    result = await curl([ '-sS', '--cacert', caFile, revokedUrl ]);
    assert.equal(result.code, 60);
    assert.match(result.stderr, /Revoked server certificate/);
    result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-options', '{"trFetchCrlPolicy":{"disabled":true}}', revokedUrl ]);
    assert.equal(result.code, 91);
    assert.match(result.stderr, /OCSP/);
    result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-options', '{"trFetchCrlPolicy":{"disabled":true}}',
                          '--tr-fetch-options', '{"trFetchOcspPolicy":{"rejectedCertificate":"ignore"}}', revokedUrl ]);
    assert.equal(result.code, 0);
    const crlFile = path.join(tmp, 'revoked.crl');
    fs.writeFileSync(crlFile, (await fixtures.crl(ca, { serials: [ 42 ] })).pem);
    result = await curl([ '-sS', '--cacert', caFile, '--crlfile', crlFile, secureUrl ]);
    assert.equal(result.code, 60);
    assert.equal((await curl([ '-sS', '--cacert', path.join(tmp, 'none.pem'), secureUrl ])).code, 77);
    assert.equal((await curl([ '-sS', '--cacert', caFile, '--crlfile', path.join(tmp, 'none.crl'), secureUrl ])).code, 82);
    assert.equal((await curl([ '-sS', '--cacert', caFile, '--tr-fetch-options', '{"trFetchCrlPolicy":"bad"}', secureUrl ])).code, 2);
});

test('--tr-fetch-* options set the CRL size limit and CRL/OCSP locations, overriding --tr-fetch-options', async function() {
    const help = (await curl([ '--help' ])).stdout;
    for (const name of [ 'max-crl-bytes <bytes>', 'crl-url <url>', 'ocsp-url <url>', 'options <json>' ]) {
        assert.match(help, new RegExp(`--tr-fetch-${name}`));
    }
    let result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-max-crl-bytes', '10', secureUrl ]);
    assert.equal(result.code, 60);
    assert.match(result.stderr, /CRL download exceeds maxCrlBytes \(10 bytes\)/);
    result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-options', '{"trFetchCrlPolicy":{"maxCrlBytes":10}}',
        '--tr-fetch-max-crl-bytes=100000', secureUrl ]);
    assert.equal(result.code, 0);
    // The size limit merges into the policy instead of replacing it: the
    // revoked CRL result is ignored, so OCSP reports the revocation.
    result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-max-crl-bytes', '100000',
        '--tr-fetch-options', '{"trFetchCrlPolicy":{"revokedCertificate":"ignore"}}', revokedUrl ]);
    assert.equal(result.code, 91);
    for (const value of [ '0', '-1', '1.5', '1k', '', '99999999999999999' ]) {
        assert.equal((await curl([ '-s', '--tr-fetch-max-crl-bytes', value, secureUrl ])).code, 2, value);
    }
    result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-crl-url', `${base}/crl-42`, secureUrl ]);
    assert.equal(result.code, 60);
    assert.match(result.stderr, /Revoked server certificate/);
    result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-options', `{"trFetchCrlDistributionPointOverride":"${base}/crl-42"}`,
        '--tr-fetch-crl-url', `${base}/crl`, secureUrl ]);
    assert.equal(result.code, 0);
    result = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-ocsp-url', `${base}/ocsp-revoked`, secureUrl ]);
    assert.equal(result.code, 91);
    for (const args of [ [ '--tr-fetch-crl-url', 'ftp://example.com/x.crl' ], [ '--tr-fetch-ocsp-url', 'not a url' ],
        [ '--tr-fetch-crl-url', `${base}/crl`, '--crlfile', caFile ] ]) {
        assert.equal((await curl([ '-s', ...args, secureUrl ])).code, 2, args.join(' '));
    }
});

test('--tr-fetch-crl-cache-scope selects the CRL cache scope; tr-curl defaults to certificate', async function() {
    assert.match((await curl([ '--help' ])).stdout, /--tr-fetch-crl-cache-scope <crl\|certificate>/);
    const scope = async args => {
        const result = await curl([ '-s', '-v', '--cacert', caFile, '-o', path.join(tmp, 'scope'), ...args, secureUrl ]);
        assert.equal(result.code, 0, args.join(' '));
        return [ result.stderr.match(/"crlCacheScope":"(\w+)"/)[1],
            /CRL authenticated while streaming/.test(result.stderr) ? 'streamed' : 'indexed' ];
    };
    assert.deepEqual(await scope([]), [ 'certificate', 'streamed' ]);
    assert.deepEqual(await scope([ '--tr-fetch-crl-cache-scope', 'crl' ]), [ 'crl', 'indexed' ]);
    assert.deepEqual(await scope([ '--tr-fetch-options', '{"trFetchCrlPolicy":{"crlCacheScope":"crl"}}' ]), [ 'crl', 'indexed' ]);
    assert.deepEqual(await scope([ '--tr-fetch-crl-cache-scope=certificate', '--tr-fetch-options', '{"trFetchCrlPolicy":{"crlCacheScope":"crl"}}' ]),
        [ 'certificate', 'streamed' ]);
    // The size limit and the scope merge into one policy.
    const merged = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-crl-cache-scope', 'crl', '--tr-fetch-max-crl-bytes', '10', secureUrl ]);
    assert.equal(merged.code, 60);
    assert.match(merged.stderr, /exceeds maxCrlBytes \(10 bytes\)/);
    for (const scope of [ 'certificate', 'crl' ]) {
        const revoked = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-crl-cache-scope', scope, revokedUrl ]);
        assert.equal(revoked.code, 60, scope);
        assert.match(revoked.stderr, /Revoked server certificate/, scope);
    }
    for (const value of [ 'CRL', 'all', '' ]) {
        assert.equal((await curl([ '-s', '--tr-fetch-crl-cache-scope', value, secureUrl ])).code, 2, value);
    }
});

test('--tr-fetch-crl-certificate-cache-size sets trFetchCrlPolicy.crlCertificateCacheSize', async function() {
    assert.match((await curl([ '--help' ])).stdout, /--tr-fetch-crl-certificate-cache-size <count>/);
    const size = async args => {
        const result = await curl([ '-s', '-v', '--cacert', caFile, '-o', path.join(tmp, 'size'), ...args, secureUrl ]);
        assert.equal(result.code, 0, args.join(' '));
        return Number(result.stderr.match(/"crlCertificateCacheSize":(-?\d+)/)[1]);
    };
    assert.equal(await size([]), 1024);
    assert.equal(await size([ '--tr-fetch-crl-certificate-cache-size', '5' ]), 5);
    assert.equal(await size([ '--tr-fetch-crl-certificate-cache-size', '0' ]), 0);
    assert.equal(await size([ '--tr-fetch-crl-certificate-cache-size', '-3' ]), -3);
    assert.equal(await size([ '--tr-fetch-options', '{"trFetchCrlPolicy":{"crlCertificateCacheSize":7}}' ]), 7);
    assert.equal(await size([ '--tr-fetch-crl-certificate-cache-size=9', '--tr-fetch-options', '{"trFetchCrlPolicy":{"crlCertificateCacheSize":7}}' ]), 9);
    for (const value of [ '1.5', '1k', '', '99999999999999999', '--' ]) {
        assert.equal((await curl([ '-s', '--tr-fetch-crl-certificate-cache-size', value, secureUrl ])).code, 2, value);
    }
});

test('--tr-fetch-ocsp-cache-size and --tr-fetch-ocsp-cache-ttl set the OCSP cache policy', async function() {
    const help = (await curl([ '--help' ])).stdout;
    assert.match(help, /--tr-fetch-ocsp-cache-size <count>/);
    assert.match(help, /--tr-fetch-ocsp-cache-ttl <seconds>/);
    const settings = async args => {
        const result = await curl([ '-s', '-v', '--cacert', caFile, '-o', path.join(tmp, 'ocsp'), ...args, secureUrl ]);
        assert.equal(result.code, 0, args.join(' '));
        return [ Number(result.stderr.match(/"ocspCacheSize":(-?\d+)/)[1]), Number(result.stderr.match(/"ocspCacheTTL":(-?\d+)/)[1]) ];
    };
    assert.deepEqual(await settings([]), [ 1024, 1800 ]);
    assert.deepEqual(await settings([ '--tr-fetch-ocsp-cache-size', '8', '--tr-fetch-ocsp-cache-ttl', '60' ]), [ 8, 60 ]);
    assert.deepEqual(await settings([ '--tr-fetch-ocsp-cache-size', '0', '--tr-fetch-ocsp-cache-ttl=-1' ]), [ 0, -1 ]);
    // Merged into the OCSP policy, over the same settings in --tr-fetch-options.
    assert.deepEqual(await settings([ '--tr-fetch-options', '{"trFetchOcspPolicy":{"ocspCacheSize":3,"ocspCacheTTL":5}}',
        '--tr-fetch-ocsp-cache-ttl', '7' ]), [ 3, 7 ]);
    const merged = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-ocsp-cache-ttl', '0',
        '--tr-fetch-options', '{"trFetchCrlPolicy":{"disabled":true},"trFetchOcspPolicy":{"rejectedCertificate":"ignore"}}', revokedUrl ]);
    assert.equal(merged.code, 0);
    for (const args of [ [ '--tr-fetch-ocsp-cache-size', '1.5' ], [ '--tr-fetch-ocsp-cache-size', 'x' ], [ '--tr-fetch-ocsp-cache-ttl', '-2' ],
        [ '--tr-fetch-ocsp-cache-ttl', '1.5' ], [ '--tr-fetch-ocsp-cache-ttl', '' ] ]) {
        assert.equal((await curl([ '-s', ...args, secureUrl ])).code, 2, args.join(' '));
    }
});

test('--tr-fetch-revocation-strategy and --tr-fetch-no-revocation-status set the certificate revocation policy', async function() {
    const help = (await curl([ '--help' ])).stdout;
    assert.match(help, /--tr-fetch-revocation-strategy <both\|ocsp-first\|crl-first>/);
    assert.match(help, /--tr-fetch-no-revocation-status <ignore\|warn\|reject>/);
    const settings = async args => {
        const result = await curl([ '-s', '-v', '--cacert', caFile, '-o', path.join(tmp, 'strategy'), ...args, secureUrl ]);
        assert.equal(result.code, 0, args.join(' '));
        return [ result.stderr.match(/"strategy":"([a-z-]+)"/)[1], result.stderr.match(/"noRevocationStatus":"([a-z]+)"/)[1],
            /CRL check skipped.*status established by OCSP/.test(result.stderr) ];
    };
    assert.deepEqual(await settings([]), [ 'both', 'ignore', false ]);
    assert.deepEqual(await settings([ '--tr-fetch-revocation-strategy', 'ocsp-first', '--tr-fetch-no-revocation-status', 'reject' ]),
                     [ 'ocsp-first', 'reject', true ]);
    assert.deepEqual(await settings([ '--tr-fetch-options', '{"trFetchCertificateRevocationPolicy":{"strategy":"crl-first"}}',
        '--tr-fetch-no-revocation-status=warn' ]), [ 'crl-first', 'warn', false ]);
    // With OCSP first, the revoked server's OCSP responder decides (exit 91).
    const revoked = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-revocation-strategy', 'ocsp-first', revokedUrl ]);
    assert.equal(revoked.code, 91);
    // No revocation status at all: exit 91, like other unverifiable statuses.
    const bare = await curl([ '-sS', '--cacert', caFile, '--tr-fetch-no-revocation-status', 'reject', bareUrl ]);
    assert.equal(bare.code, 91);
    assert.match(bare.stderr, /No revocation status established/);
    for (const args of [ [ '--tr-fetch-revocation-strategy', 'either' ], [ '--tr-fetch-no-revocation-status', 'allow' ] ]) {
        assert.equal((await curl([ '-s', ...args, secureUrl ])).code, 2, args.join(' '));
    }
});

test('--insecure bypasses TLS verification and revocation checks', async function() {
    assert.equal((await curl([ '-s', untrustedUrl ])).code, 60);
    let result = await curl([ '-s', '-k', untrustedUrl ]);
    assert.equal(result.code, 0);
    assert.equal(result.stdout, 'secure');
    result = await curl([ '-s', '-k', '-v', revokedUrl ]);
    assert.equal(result.code, 0);
    assert.match(result.stderr, /--insecure disables TLS verification and trFetch CRL\/OCSP revocation checks/);
    assert.doesNotMatch(result.stderr, /\[trFetch debug/);
});

test('TLS version and cipher options', async function() {
    const leaf = await fixtures.certificate({ issuer: ca, serial: 44 });
    const tls12 = https.createServer({ cert: leaf.pem, key: leaf.key, maxVersion: 'TLSv1.2' }, (req, res) => res.end('tls12'));
    const url = `https://localhost:${await listen(tls12)}/`;
    const common = [ '-sS', '--cacert', caFile, '--tr-fetch-options',
                     '{"trFetchCrlPolicy":{"disabled":true},"trFetchOcspPolicy":{"disabled":true}}' ];
    try {
        assert.equal((await curl([ ...common, '--tlsv1.2', url ])).stdout, 'tls12');
        assert.equal((await curl([ ...common, '--tlsv1.3', url ])).code, 35);
        assert.equal((await curl([ ...common, '--tls-max', '1.2', '--ciphers', 'ECDHE-ECDSA-AES128-GCM-SHA256', url ])).code, 0);
        assert.equal((await curl([ ...common, '--ciphers', 'NO-SUCH-CIPHER', url ])).code, 59);
        assert.equal((await curl([ ...common, '--tls13-ciphers', 'TLS_AES_128_GCM_SHA256', '--tlsv1.3', secureUrl ])).code, 0);
        assert.equal((await curl([ ...common, '--tlsv1.3', '--tls-max', '1.2', url ])).code, 2);
    } finally {
        tls12.closeAllConnections();
        await new Promise(resolve => tls12.close(resolve));
    }
});

test('--verbose shows request, response and trFetch debug output', async function() {
    const result = await curl([ '-s', '-v', '-u', 'joe:pw', '--cacert', caFile, secureUrl ]);
    assert.equal(result.code, 0);
    assert.match(result.stderr, /^> GET \/ HTTP\/1\.1$/m);
    assert.match(result.stderr, /^> Authorization: Basic /m);
    assert.match(result.stderr, /^< HTTP\/1\.1 200 OK$/m);
    assert.match(result.stderr, /^\[trFetch debug #\d+\] CRL serial lookup completed .*"result":"not listed"/m);
    assert.match(result.stderr, /^\[trFetch debug #\d+\] OCSP check completed .*"result":"good"/m);
    assert.doesNotMatch((await curl([ '-s', '--cacert', caFile, secureUrl ])).stderr, /trFetch debug/);
});
