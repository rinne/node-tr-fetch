'use strict';

const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');
const tty = require('node:tty');
const { Agent } = require('undici');
const trFetch = require('..');
const { parseArguments, helpText } = require('./options');
const Progress = require('./progress');
const { version } = require('../package.json');

const REDIRECTS = [ 301, 302, 303, 307, 308 ];
// Undici owns these; fetch would ignore or reject caller-supplied values.
const FETCH_CONTROLLED = [ 'host', 'connection', 'content-length', 'keep-alive', 'transfer-encoding', 'upgrade', 'expect' ];
const CERTIFICATE_ERROR = /^(CERT_|UNABLE_TO_|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|INVALID_CA|INVALID_PURPOSE|PATH_LENGTH_EXCEEDED|HOSTNAME_MISMATCH|ERR_TLS_CERT_ALTNAME_INVALID)/;

class CurlError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}

function report(config, code, message) {
    if ((message !== undefined) && (! config.silent || config.showError)) {
        process.stderr.write(`tr-curl: (${code}) ${message}\n`);
    }
}

function verbose(config, prefix, lines) {
    if (config.verbose) {
        process.stderr.write(lines.map(line => `${prefix} ${line}`.trimEnd() + '\n').join(''));
    }
}

function writeStdout(chunk) {
    return new Promise(function(resolve, reject) {
        process.stdout.write(chunk, error => error ? reject(error) : resolve());
    });
}

async function readInput(name, cache) {
    if (name === '-') {
        if (cache.stdin === undefined) {
            const chunks = [];
            for await (const chunk of process.stdin) {
                chunks.push(chunk);
            }
            cache.stdin = Buffer.concat(chunks);
        }
        return cache.stdin;
    }
    try {
        return await fs.promises.readFile(name);
    } catch (error) {
        throw new CurlError(26, `Failed to open ${name}: ${error.message}`);
    }
}

function urlencode(value) {
    return encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

async function requestBody(config, cache) {
    let body;
    for (const { kind, value } of config.data) {
        let piece;
        if ((kind === 'raw') || ! value.startsWith('@') || (kind === 'urlencode')) {
            piece = Buffer.from(value);
        } else {
            piece = await readInput(value.slice(1), cache);
            if (kind === 'data') {
                piece = Buffer.from(piece.filter(x => (x !== 0x0d) && (x !== 0x0a)));
            }
        }
        if (kind === 'urlencode') {
            const match = value.match(/^([^=@]*)([=@])([^]*)$/);
            if (! match) {
                piece = Buffer.from(urlencode(value));
            } else {
                const content = (match[2] === '@') ? (await readInput(match[3], cache)).toString() : match[3];
                piece = Buffer.from((match[1] ? `${match[1]}=` : '') + urlencode(content));
            }
        }
        const separator = ((body !== undefined) && (kind !== 'json')) ? Buffer.from('&') : Buffer.alloc(0);
        body = Buffer.concat([ body ?? Buffer.alloc(0), separator, piece ]);
    }
    return body;
}

async function customHeaders(config, cache) {
    const lines = [];
    for (const value of config.headers) {
        if (value.startsWith('@')) {
            lines.push(...(await readInput(value.slice(1), cache)).toString().split(/\r?\n/).filter(x => x.trim()));
        } else {
            lines.push(value);
        }
    }
    const headers = [];
    for (const line of lines) {
        // "Name:" removes an internal header and "Name;" sends an empty one.
        const match = line.match(/^([^:;\s]+)\s*(?::\s*([^]*?)\s*|;\s*)$/);
        if (! match) {
            process.stderr.write(`Warning: ignoring malformed header ${JSON.stringify(line)}\n`);
            continue;
        }
        const value = (match[2] === undefined) ? '' : match[2];
        if (FETCH_CONTROLLED.includes(match[1].toLowerCase())) {
            process.stderr.write(`Warning: fetch controls the ${match[1]} header; ignoring it\n`);
            continue;
        }
        headers.push({ name: match[1], value: (line.includes(':') && (value === '')) ? null : value });
    }
    return headers;
}

function promptPassword(user) {
    return new Promise(function(resolve) {
        let input;
        try {
            input = new tty.ReadStream(fs.openSync('/dev/tty', 'r'));
            input.setRawMode(true);
        } catch (_) {
            input?.destroy();
            resolve('');
            return;
        }
        process.stderr.write(`Enter host password for user '${user}':`);
        let password = '';
        input.setEncoding('utf8');
        input.on('data', function(text) {
            for (const c of text) {
                if ((c === '\r') || (c === '\n') || (c === '\u0004')) {
                    input.setRawMode(false);
                    input.destroy();
                    process.stderr.write('\n');
                    resolve(password);
                    return;
                } else if (c === '\u0003') {
                    input.setRawMode(false);
                    process.stderr.write('\n');
                    process.exit(130);
                } else if ((c === '\u007f') || (c === '\b')) {
                    password = password.slice(0, -1);
                } else {
                    password += c;
                }
            }
        });
    });
}

function readFileOrFail(file, code, message) {
    try {
        return fs.readFileSync(file);
    } catch (error) {
        throw new CurlError(code, `${message} ${file}: ${error.message}`);
    }
}

// TLS settings are process wide, which is fine for a command line tool, and
// apply to trFetch connections without weakening its verification.
function setupTls(config) {
    if (config.tlsMax !== undefined) {
        tls.DEFAULT_MAX_VERSION = config.tlsMax;
        if (config.tlsMin === undefined) {
            tls.DEFAULT_MIN_VERSION = [ tls.DEFAULT_MIN_VERSION, config.tlsMax ].sort()[0];
        }
    }
    if (config.tlsMin !== undefined) {
        tls.DEFAULT_MIN_VERSION = config.tlsMin;
    }
    if ((config.ciphers !== undefined) || (config.tls13Ciphers !== undefined)) {
        const current = tls.DEFAULT_CIPHERS.split(':');
        const tls13 = config.tls13Ciphers ?? current.filter(x => x.startsWith('TLS_')).join(':');
        const tls12 = config.ciphers ?? current.filter(x => ! x.startsWith('TLS_')).join(':');
        const ciphers = [ tls13, tls12 ].filter(Boolean).join(':');
        if (tls13.split(':').some(x => ! x.startsWith('TLS_')) || tls12.split(':').some(x => x.startsWith('TLS_'))) {
            throw new CurlError(59, `failed setting cipher list: ${ciphers}`);
        }
        try {
            tls.createSecureContext({ ciphers });
        } catch (_) {
            throw new CurlError(59, `failed setting cipher list: ${ciphers}`);
        }
        tls.DEFAULT_CIPHERS = ciphers;
    }
    if (config.cacert !== undefined) {
        const certificates = readFileOrFail(config.cacert, 77, 'error setting certificate file')
              .toString().match(/-----BEGIN CERTIFICATE-----[^]+?-----END CERTIFICATE-----/g);
        if (! certificates) {
            throw new CurlError(77, `error setting certificate file ${config.cacert}: no PEM certificates`);
        }
        try {
            tls.setDefaultCACertificates(certificates);
        } catch (error) {
            throw new CurlError(77, `error setting certificate file ${config.cacert}: ${error.message}`);
        }
    }
}

async function prepare(config) {
    const cache = {};
    setupTls(config);
    const trFetchOptions = { ...config.trFetchOptions };
    if (config.crlFile !== undefined) {
        trFetchOptions.trFetchCrlOverride = readFileOrFail(config.crlFile, 82, 'error loading CRL file');
    }
    let user;
    if (config.user !== undefined) {
        const separator = config.user.indexOf(':');
        user = (separator < 0) ? { name: config.user, password: await promptPassword(config.user) } :
        { name: config.user.slice(0, separator), password: config.user.slice(separator + 1) };
    }
    let etag;
    if (config.etagCompare !== undefined) {
        try {
            etag = fs.readFileSync(config.etagCompare, 'utf8').split(/\r?\n/)[0].trim();
        } catch (error) {
            process.stderr.write(`Warning: Failed to open ${config.etagCompare}: ${error.message}\n`);
        }
        etag ||= '""';
    }
    let referer, refererAuto = false;
    if (config.referer !== undefined) {
        refererAuto = config.referer.endsWith(';auto');
        referer = refererAuto ? config.referer.slice(0, -5) : config.referer;
    }
    return { headers: await customHeaders(config, cache), body: await requestBody(config, cache),
             user, etag, referer, refererAuto, trFetchOptions };
}

function parseUrl(value, base) {
    let url;
    if (base === undefined) {
        value = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`;
        const scheme = value.slice(0, value.indexOf(':')).toLowerCase();
        if (! [ 'http', 'https' ].includes(scheme)) {
            throw new CurlError(1, `Protocol "${scheme}" not supported`);
        }
    }
    try {
        url = new URL(value, base);
    } catch (_) {
        throw new CurlError(3, 'URL rejected: Malformed input to a URL function');
    }
    if (! [ 'http:', 'https:' ].includes(url.protocol)) {
        throw new CurlError(1, `Protocol "${url.protocol.slice(0, -1)}" not supported`);
    }
    return url;
}

function outputFile(config, index, url) {
    let name;
    if (index < config.outputs.length) {
        name = config.outputs[index];
        if (name === '-') {
            return { explicit: true };
        }
    } else if (config.remoteNameAll || (index < config.remoteName)) {
        name = url.pathname.slice(url.pathname.lastIndexOf('/') + 1);
        if (! name) {
            throw new CurlError(23, 'Remote file name has no length');
        }
    } else {
        return { explicit: false };
    }
    if ((config.outputDir !== undefined) && ! path.isAbsolute(name)) {
        name = path.join(config.outputDir, name);
    }
    return { file: name };
}

class Output {
    #config;
#file;
    #handle;
    created = false;

    constructor(config, file) {
        this.#config = config;
        this.#file = file;
    }

    get isFile() {
        return this.#file !== undefined;
    }

    async open() {
        if ((this.#file === undefined) || this.#handle) {
            return;
        }
        try {
            if (this.#config.createDirs) {
                await fs.promises.mkdir(path.dirname(this.#file), { recursive: true });
            }
            this.#handle = await fs.promises.open(this.#file, 'w');
            this.created = true;
        } catch (error) {
            throw new CurlError(23, `Failed to open the file ${this.#file}: ${error.message}`);
        }
    }

    async write(chunk) {
        try {
            if (this.#file === undefined) {
                await writeStdout(chunk);
            } else {
                await this.open();
                await this.#handle.write(chunk);
            }
        } catch (error) {
            throw (error instanceof CurlError) ? error : new CurlError(23, `Failure writing output to destination: ${error.message}`);
        }
    }

    async close() {
        await this.#handle?.close();
        this.#handle = undefined;
    }

    async remove() {
        await this.close();
        if (this.created) {
            await fs.promises.rm(this.#file, { force: true });
        }
    }
}

function failure(error, url, gotResponse) {
    if (error instanceof CurlError) {
        return error;
    }
    if (error instanceof trFetch.TrFetchCrlError) {
        return new CurlError(60, error.message);
    }
    // OCSP rejections, and no status from any check: the certificate status
    // could not be verified.
    if ((error instanceof trFetch.TrFetchOcspError) || (error instanceof trFetch.TrFetchRevocationError)) {
        return new CurlError(91, error.message);
    }
    const causes = [];
    for (let cause = error; cause && (causes.length < 10); cause = cause.cause) {
        causes.push(cause);
    }
    const cause = causes.find(x => typeof(x.code) === 'string') ?? causes.at(-1);
    const code = cause?.code ?? '';
    const message = cause?.message ?? String(error);
    url ??= new URL('http://unknown/');
    const port = url.port || ((url.protocol === 'https:') ? 443 : 80);
    if (/^(ENOTFOUND|EAI_)/.test(code)) {
        return new CurlError(6, `Could not resolve host: ${url.hostname}`);
    }
    if ([ 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EADDRNOTAVAIL', 'ETIMEDOUT' ].includes(code) || (message === 'bad port')) {
        return new CurlError(7, `Failed to connect to ${url.hostname} port ${port}: ${message}`);
    }
    if ([ 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT' ].includes(code)) {
        return new CurlError(28, message);
    }
    if (CERTIFICATE_ERROR.test(code) || message.startsWith('TLS certificate verification failed')) {
        return new CurlError(60, `SSL certificate problem: ${message}`);
    }
    if (/^ERR_(SSL|TLS)_/.test(code) || (code === 'EPROTO')) {
        return new CurlError(35, `TLS connect error: ${message}`);
    }
    if (code.startsWith('HPE_') || (cause?.name === 'HTTPParserError')) {
        return new CurlError(8, `Weird server reply: ${message}`);
    }
    if ((code === 'UND_ERR_SOCKET') && ! gotResponse) {
        return new CurlError(52, 'Empty reply from server');
    }
    if ((error instanceof TypeError) && (error.message !== 'fetch failed') && (error.message !== 'terminated')) {
        // Request construction or trFetch option errors.
        return new CurlError(2, error.message);
    }
    return new CurlError(56, `Failure when receiving data from the peer: ${message}`);
}

function requestHeaders(config, prep, state) {
    const internal = [];
    const crossOrigin = (state.url.origin !== state.authOrigin) && ! config.locationTrusted;
    internal.push([ 'User-Agent', config.userAgent ?? `tr-curl/${version}` ]);
    internal.push([ 'Accept', config.json ? 'application/json' : '*/*' ]);
    if ((state.authorization !== undefined) && ! crossOrigin) {
        internal.push([ 'Authorization', state.authorization ]);
    }
    if (state.referer) {
        internal.push([ 'Referer', state.referer ]);
    }
    if (config.range !== undefined) {
        internal.push([ 'Range', `bytes=${config.range}` ]);
    }
    if (prep.etag !== undefined) {
        internal.push([ 'If-None-Match', prep.etag ]);
    }
    if (state.body !== undefined) {
        internal.push([ 'Content-Type', config.json ? 'application/json' : 'application/x-www-form-urlencoded' ]);
    }
    // Custom headers replace internal ones, and credentials stay on the
    // original origin like curl unless --location-trusted is given.
    const custom = prep.headers.filter(x => ! (crossOrigin && [ 'authorization', 'cookie' ].includes(x.name.toLowerCase())));
    const replaced = new Set(custom.map(x => x.name.toLowerCase()));
    return [ ...internal.filter(([name]) => ! replaced.has(name.toLowerCase())),
             ...custom.filter(x => x.value !== null).map(x => [ x.name, x.value ]) ];
}

function headerBlock(response) {
    const lines = [ `HTTP/1.1 ${response.status} ${response.statusText}`.trimEnd() ];
    for (const [name, value] of response.headers) {
        lines.push(`${name}: ${value}`);
    }
    return lines;
}

async function send(config, prep, url, init) {
    if (! config.insecure) {
        return trFetch(url, { trFetchDebug: config.verbose, ...prep.trFetchOptions, ...init });
    }
    const agent = new Agent({ allowH2: false, connect: { rejectUnauthorized: false } });
    try {
        const response = await globalThis.fetch(url, { ...init, dispatcher: agent });
        void agent.close().catch(() => {});
        return response;
    } catch (error) {
        await agent.destroy();
        throw error;
    }
}

async function exchange(config, prep, rawUrl, index, context) {
    const initial = parseUrl(rawUrl);
    const target = outputFile(config, index, initial);
    const output = context.output = new Output(config, target.file);
    const state = context.state = { url: new URL(initial), authOrigin: initial.origin, referer: prep.referer, body: prep.body };
    const signal = context.signal;
    if (initial.username || initial.password) {
        state.authorization = 'Basic ' + Buffer.from(`${decodeURIComponent(initial.username)}:${decodeURIComponent(initial.password)}`).toString('base64');
        state.url.username = '';
        state.url.password = '';
    }
    if (prep.user !== undefined) {
        state.authorization = 'Basic ' + Buffer.from(`${prep.user.name}:${prep.user.password}`).toString('base64');
    }
    if (config.bearer !== undefined) {
        state.authorization = `Bearer ${config.bearer}`;
    }
    if (config.get && (state.body !== undefined)) {
        state.url.search = state.url.search ? `${state.url.search}&${state.body}` : `?${state.body}`;
        state.body = undefined;
    }
    let method = config.request ?? (config.head ? 'HEAD' : ((state.body !== undefined) ? 'POST' : 'GET'));
    const showHeaders = config.include || config.head;
    if (config.insecure) {
        verbose(config, '*', [ 'WARNING: --insecure disables TLS verification and trFetch CRL/OCSP revocation checks' ]);
    }
    let response;
    for (let redirects = 0; ; redirects++) {
        const headers = requestHeaders(config, prep, state);
        verbose(config, '*', [ `Fetching ${state.url.origin} with ${config.insecure ? 'plain fetch' : 'trFetch'}` ]);
        verbose(config, '>', [ `${method} ${state.url.pathname}${state.url.search} HTTP/1.1`, `Host: ${state.url.host}`,
                               ...headers.map(([name, value]) => `${name}: ${value}`), '' ]);
        verbose(config, '*', [ 'fetch adds headers of its own, such as Connection, Accept-Language, Sec-Fetch-Mode and Accept-Encoding' ]);
        response = await send(config, prep, state.url, { method, headers, body: state.body, redirect: 'manual', signal });
        context.gotResponse = true;
        context.progress?.upload(state.body?.length ?? 0);
        const lines = headerBlock(response);
        verbose(config, '<', [ ...lines, '' ]);
        const location = response.headers.get('location');
        const follow = config.location && REDIRECTS.includes(response.status) && (location !== null);
        if (! follow && (config.fail || config.failWithBody) && (response.status >= 400)) {
            if (config.fail) {
                await response.body?.cancel();
                throw new CurlError(22, `The requested URL returned error: ${response.status}`);
            }
            context.failed = new CurlError(22, `The requested URL returned error: ${response.status}`);
        }
        if (showHeaders) {
            await output.write(lines.join('\r\n') + '\r\n\r\n');
        }
        if (! follow) {
            break;
        }
        await response.body?.cancel();
        if ((config.maxRedirs !== -1) && (redirects >= config.maxRedirs)) {
            throw new CurlError(47, `Maximum (${config.maxRedirs}) redirects followed`);
        }
        const next = parseUrl(location, state.url);
        next.hash = '';
        verbose(config, '*', [ `Issue another request to this URL: '${next.href}'` ]);
        if ((response.status === 303) ? (method !== 'HEAD') : ((response.status <= 302) && (method === 'POST'))) {
            // Browsers and curl switch to GET here; -X keeps its method string.
            method = config.request ?? 'GET';
            state.body = undefined;
        }
        if (prep.refererAuto) {
            const previous = new URL(state.url);
            previous.hash = '';
            state.referer = previous.href;
        }
        state.url = next;
    }
    if (config.head || (method === 'HEAD') || ! response.body) {
        await response.body?.cancel();
        return;
    }
    const encoded = response.headers.has('content-encoding');
    const length = encoded ? NaN : Number(response.headers.get('content-length') ?? NaN);
    const total = Number.isSafeInteger(length) ? length : undefined;
    if ((config.maxFilesize !== undefined) && (total > config.maxFilesize)) {
        await response.body.cancel();
        throw new CurlError(63, 'Maximum file size exceeded');
    }
    context.progress?.expect(total);
    const checkBinary = ! output.isFile && ! target.explicit && process.stdout.isTTY;
    const iterator = response.body[Symbol.asyncIterator]();
    for (;;) {
        let step;
        try {
            step = await iterator.next();
        } catch (error) {
            if (signal?.aborted || (error instanceof CurlError)) {
                throw error;
            }
            throw (total !== undefined) ?
                new CurlError(18, `transfer closed with ${total - context.received} bytes remaining to read`) :
                failure(error, state.url, true);
        }
        if (step.done) {
            break;
        }
        const chunk = step.value;
        if (checkBinary && (context.received === 0) && chunk.includes(0)) {
            await iterator.return();
            process.stderr.write('Warning: Binary output can mess up your terminal. Use "--output -" to tell\n' +
                                 'Warning: tr-curl to output it to your terminal anyway, or consider "--output\n' +
                                 'Warning: <FILE>" to save to a file.\n');
            throw new CurlError(23);
        }
        context.received += chunk.length;
        if ((config.maxFilesize !== undefined) && (context.received > config.maxFilesize)) {
            await iterator.return();
            throw new CurlError(63, 'Maximum file size exceeded');
        }
        await output.write(chunk);
        context.progress?.update(context.received);
    }
}

async function transfer(config, prep, rawUrl, index) {
    const started = Date.now();
    const timeout = (config.maxTime === undefined) ? undefined : Math.max(1, Math.round(config.maxTime * 1000));
    const context = { received: 0, gotResponse: false, state: undefined,
                      signal: (timeout === undefined) ? undefined : AbortSignal.timeout(timeout) };
    const toStdout = (index >= config.outputs.length) && ! config.remoteNameAll && (index >= config.remoteName) ||
          (config.outputs[index] === '-');
    if (! config.silent && (config.progressBar || (config.progressMeter && ! (toStdout && process.stdout.isTTY)))) {
        context.progress = new Progress(config.progressBar ? 'bar' : 'meter');
    }
    let error;
    try {
        await exchange(config, prep, rawUrl, index, context);
        error = context.failed;
    } catch (caught) {
        error = (context.signal?.aborted && ! (caught instanceof CurlError)) ?
            new CurlError(28, `Operation timed out after ${Date.now() - started} milliseconds with ${context.received} bytes received`) :
            failure(caught, context.state?.url, context.gotResponse);
    }
    context.progress?.finish();
    try {
        if (error && config.removeOnError) {
            await context.output?.remove();
        } else if (! error || (error === context.failed)) {
            // Like curl, a successful transfer creates the file even when empty.
            await context.output?.open();
        }
        await context.output?.close();
    } catch (caught) {
        error ??= failure(caught, context.state?.url);
    }
    if (error) {
        report(config, error.code, error.message);
        return error.code;
    }
    verbose(config, '*', [ `Transfer complete: ${context.received} bytes received in ${(Date.now() - started) / 1000} s` ]);
    return 0;
}

async function main(argv) {
    let config;
    try {
        config = parseArguments(argv);
    } catch (error) {
        process.stderr.write(`tr-curl: ${error.message}\ntr-curl: try 'tr-curl --help' for more information\n`);
        return 2;
    }
    if (config.help) {
        process.stdout.write(helpText());
        return 0;
    }
    if (config.version) {
        process.stdout.write(`tr-curl ${version} (tr-fetch ${version}) Node.js/${process.version} ` +
                             `undici/${process.versions.undici} OpenSSL/${process.versions.openssl}\n` +
                             'Protocols: http https\nFeatures: Basic-auth Bearer-auth CRL OCSP SSL\n');
        return 0;
    }
    if (! config.urls.length) {
        process.stderr.write('tr-curl: no URL specified\ntr-curl: try \'tr-curl --help\' for more information\n');
        return 2;
    }
    // A closed pipe is reported through the write callback as exit code 23.
    process.stdout.on('error', () => {});
    let prep;
    try {
        prep = await prepare(config);
    } catch (error) {
        const failed = (error instanceof CurlError) ? error : new CurlError(2, error.message);
        report(config, failed.code, failed.message);
        return failed.code;
    }
    let result = 0;
    for (let index = 0; index < config.urls.length; index++) {
        const code = await transfer(config, prep, config.urls[index], index);
        if (code) {
            result = code;
            if (config.failEarly) {
                break;
            }
        }
    }
    return result;
}

module.exports = { main };
