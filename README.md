# tr-fetch

Node.js `fetch()` with certificate revocation list (CRL) and OCSP checking.
Plain JavaScript, CommonJS, no build step. Requires Node.js 26 or later.

```js
const trFetch = require('tr-fetch');

const response = await trFetch('https://example.com/');
console.log(await response.text());
```

ES module default imports work too:

```js
import trFetch from 'tr-fetch';
```

The function calls Node's system `fetch()` and returns its native `Response`.
It accepts the usual string, `URL` or `Request` input and fetch options,
including streaming bodies, redirects and abort signals.

## Options

```js
const response = await trFetch(url, {
	method: 'GET',
	trFetchDebug: false,
	trFetchCrlPolicy: {
		disabled: false,
		maxCrlBytes: 16777216,
		crlCacheScope: 'crl',
		crlCacheSize: 32,
		crlCertificateCacheSize: 1024,
		crlCacheTTL: 1800,
		crlCheckDepth: 0,
		missingCrlDistributionPoint: 'ignore',
		unreachableCrlDistributionPoint: 'reject',
		invalidCrl: 'reject',
		revokedCertificate: 'reject'
	},
	trFetchOcspPolicy: {
		disabled: false,
		ocspCacheSize: 1024,
		ocspCacheTTL: 1800,
		ocspCheckDepth: 0,
		missingOcspUri: 'ignore',
		unreachableOcspUri: 'reject',
		rejectedCertificate: 'reject'
	}
});
```

These are the defaults. Policy objects may specify only the properties to
change. Both checks are enabled by default and operate independently. Each
failure policy (in the table below) accepts `'ignore'`, `'warn'` or
`'reject'`; the other policy settings are described in their own sections.

| Policy | Condition |
|---|---|
| `missingCrlDistributionPoint` | The checked certificate has no CRL distribution points extension and no applicable override. |
| `unreachableCrlDistributionPoint` | No usable network location, a forbidden URI scheme, download failure, non-200 response, timeout, excessive redirects or download size. |
| `invalidCrl` | Malformed data, wrong issuer, bad signature, invalid signing permission, invalid dates, expired CRL, mismatched scope or unsupported CRL features. |
| `revokedCertificate` | The certificate serial is present in a successfully authenticated, applicable CRL. |
| `missingOcspUri` | No OCSP access location is advertised in the certificate's Authority Information Access extension, and no applicable override is set. |
| `unreachableOcspUri` | Forbidden URI scheme, download failure, non-200 HTTP response, timeout, excessive redirects or response size. |
| `rejectedCertificate` | OCSP reports revoked or unknown; or the response is malformed, unsuccessful, stale, incorrectly signed, unauthorized, mismatched or otherwise unsupported. |

`ignore` continues without a warning. `warn` emits a Node.js process warning and
continues. `reject` rejects the fetch promise before sending the HTTP request
on that connection. These policies apply only to revocation checks; they cannot
relax normal TLS verification.

### CRL size limit

`trFetchCrlPolicy.maxCrlBytes` is the largest CRL accepted, in bytes. It
defaults to `16777216` (16 MiB) and must be a positive safe integer; there is
no value for unlimited. Some public CAs publish much larger CRLs, so raise it
explicitly when needed:

```js
await trFetch('https://example.com/', { trFetchCrlPolicy: { maxCrlBytes: 64 * 1024 * 1024 } });
```

A larger download is an unreachable distribution point; larger
`trFetchCrlOverride` data is an invalid CRL. A cached CRL or result from a CRL
above the caller's limit is not used, even if an earlier caller with a higher
limit cached it.

With `crlCacheScope: 'crl'`, the CRL is downloaded into a single buffer,
verified and scanned in place, and only its serial numbers are kept. Peak
memory while fetching a CRL is roughly three to four times its size, most of
it in Node's HTTP stream buffering, and is released afterwards. With
`'certificate'`, the CRL is never held in memory and the limit bounds only the
download; see [CRL cache scope](#crl-cache-scope).

### CRL cache scope

`trFetchCrlPolicy.crlCacheScope` selects how CRLs are processed and what the
cache keeps. Only `'crl'` (the default) and `'certificate'` are accepted.

| | `'crl'` | `'certificate'` |
|---|---|---|
| Processing | Downloaded, then authenticated and indexed | Checked while streaming; never held |
| Cached | Every revoked serial of the CRL | Whether the CRL lists each checked certificate |
| Another certificate of the same CRL | Answered from the cache | Downloads the CRL again, unless cached as a candidate (see below) |
| Peak memory for a 43 MB CRL | about 135–165 MB | about 40–47 MB |
| Cached memory for that CRL | 14 MB | tens of bytes per certificate |

`'crl'` suits clients that talk to many servers whose certificates share a
CRL. `'certificate'` suits clients that talk to few servers, or that meet very
large CRLs.

In `'certificate'` scope, the CRL signature is computed as the CRL arrives,
and every revoked entry is checked as with `'crl'`. Nothing is decided until
the whole CRL has been read and authenticated; reading stops early only at
invalid content. A PEM CRL is collected within `maxCrlBytes` and decoded
first. Cache entries are keyed by the issuer certificate, the checked
certificate and the distribution URL:

- An entry answers until the earlier of the CRL's `nextUpdate` and the TTL.
  It records that the certificate is listed or not listed; both are cached.
- After that, it is **stale**: never an answer, but a candidate. Whenever the
  CRL is downloaded for any certificate of the same issuer and URL, all
  candidates, fresh or stale, are checked in the same pass and refreshed. The
  CRL's scope is checked again for each; a candidate it no longer covers is
  dropped.
- A result from an older CRL (by `thisUpdate`) never replaces one from a newer
  CRL, so a stale mirror cannot roll a revocation back.
- Stale candidates are dropped after a day without lookups. Refreshes do not
  count as lookups, neither for staleness nor for LRU order.
- `trFetchCrlOverride` data is checked directly and never cached.

A download failure or an invalid CRL leaves other entries unchanged. The CRL
cache and this result cache are separate: `crlCacheSize` limits the first
and `crlCertificateCacheSize` the second, and `crlCacheTTL` applies to both
(see [Cache](#cache)).

### Disabling a check

Both policy objects accept `disabled`. It defaults to `false`; `undefined` and
`null` also mean `false`. Only boolean `true` disables the corresponding check.
Other types reject with `TypeError`.

```js
await trFetch(url, {
	trFetchCrlPolicy: { disabled: true },
	trFetchOcspPolicy: { disabled: true }
});
```

A disabled check performs no certificate revocation inspection, cache access,
responder lookup or warning emission. Its depth and overrides are not used.
Options are still validated. Disabling either check leaves the other enabled;
disabling both retains mandatory normal TLS trust and hostname verification.

Unknown `trFetch...` options, unknown policy keys and invalid option values
reject with `TypeError`. Custom options are removed before the request reaches
system fetch. The caller's options are not modified.

### Debug output

Set `trFetchDebug: true` to write verification diagnostics to **stderr**:

```js
await trFetch('https://example.com/', { trFetchDebug: true });
```

The default is `false` (also when omitted or `undefined`); other values,
including `null`, reject with `TypeError`. This option is removed before
calling system fetch.

Each line starts with `[trFetch debug #N]`, followed by an event and JSON details.
The ID groups events from the same fetch, including redirects, when calls run
concurrently. Certificate events identify the hostname, serial number, and
`leaf` at depth `0` or `intermediate CA` at depth `1` and above.

Diagnostics cover discovered CRL distribution points and OCSP URIs, overrides,
downloads and redirects, parsing, authenticated serial/status results, and
policy actions (`ignore`, `warn`, `reject`, or `continue` for successful checks).
Cache events report hits, misses, storage, bypass, expiration by TTL or CRL
validity, and LRU purges. Expiration and purge events appear when cache access
actually removes entries; there is no background expiration timer.

For example, a successful OCSP result includes:

```text
[trFetch debug #1] OCSP check completed {"hostname":"example.com","certificate":"leaf","depth":0,"serial":"2A","source":"https://ca.example/ocsp","result":"good","authenticated":true,"policy":"rejectedCertificate","configuredAction":"reject","action":"continue","nextUpdate":1790500000000}
```

An unusable candidate is logged as a detected condition; its failure policy is
applied only if no usable alternative exists. Parsing alone does not indicate
authentication. Disabled checks and excluded trust anchors are identified.
Debugging does not change verification, caching, warnings or rejection behavior,
and enabling it for one fetch does not enable it for other calls.

Logged URLs omit credentials, query strings and fragments. Request headers,
request/response bodies and raw certificate/CRL data are not logged. Hostnames,
URL paths and certificate serial numbers remain visible.

### Check depth

`trFetchCrlPolicy.crlCheckDepth` and `trFetchOcspPolicy.ocspCheckDepth` are
independent settings with the same values:

| Value | Certificates checked |
|---|---|
| `0` or `'leaf'` (default) | The server certificate. |
| `1` | The server certificate and its first intermediate CA. |
| `n` | The server certificate and up to `n` intermediate CAs. |
| `'full-chain'` | All certificates exposed by the verified TLS chain, excluding its trust anchor. |

Numeric depths must be nonnegative safe integers. The trust anchor is excluded
at every depth; trust in it is established by Node's CA configuration. The
server certificate is checked whenever that check is enabled, including when
explicitly trusted and self-signed. Chain traversal has a defensive limit of
32 certificates.

The same policies apply at every selected depth. Each intermediate uses its
own distribution points or OCSP URIs. Overrides apply only to the server
certificate. A successful check does not override a rejection from the other
enabled check.

### Overrides

Set **one** of these options:

```js
await trFetch(url, {
	trFetchCrlDistributionPointOverride: 'https://ca.example.com/current.crl'
});

await trFetch(url, {
	trFetchCrlOverride: crlBytes
});
```

`trFetchCrlDistributionPointOverride` accepts an absolute URL string or `URL`.
`trFetchCrlOverride` accepts a PEM string, `Buffer`, `Uint8Array` or
`ArrayBuffer` containing one complete PEM or DER CRL. It is data, never a file
path. Supplying both options rejects with `TypeError`.

Either override bypasses the server certificate's advertised distribution
points. Override CRLs still require a valid signature from the actual issuer,
appropriate signing permission, valid dates and applicable scope. A directly
supplied CRL with a named issuing distribution point cannot establish a match
to an effective network distribution point and is rejected as `invalidCrl`.
Direct override data is copied and is not put in the download cache.

`trFetchOcspUriOverride` independently accepts an absolute URL string or `URL`:

```js
await trFetch(url, {
	trFetchOcspUriOverride: 'https://ca.example.com/ocsp'
});
```

It replaces the leaf certificate's advertised OCSP URIs. It can be used with
either CRL override. Responses from the forced URI still require authentication
and a matching certificate identifier. Intermediates use their own OCSP URIs.

### Cache

Fetched and validated CRLs share an in-memory LRU cache within the loaded
module. Cache keys include the issuer certificate and distribution URL.
Certificate decisions, failed lookups and `trFetchCrlOverride` data are never
cached.

The cache does not keep the CRL itself. After a CRL is authenticated, its
revoked serial numbers are stored as sorted fixed-width records, one array per
serial length, together with the CRL's validity period and scope. Memory is
about the size of the serial numbers (14 MB for a 43 MB CRL of 875,000
entries), outside the JavaScript heap, and a lookup is a binary search.
Serials match only by identical DER bytes.

Checks that depend only on the CRL and its issuer, including the signature,
run once per download. Checks that depend on the certificate or the time run
on every use: validity dates, scope and distribution point, the certificate's
issuer name and signature, and the serial lookup. An entry serves only the
issuer certificate that authenticated it.

The cache settings are in `trFetchCrlPolicy`:

- `crlCacheSize` limits the CRL cache of scope `'crl'`, and defaults to `32`
  CRLs. `crlCertificateCacheSize` limits the per-certificate results of scope
  `'certificate'`, and defaults to `1024` certificates. Any integer **0 or
  less** disables that cache for the call; `null` means the default.
- `crlCacheTTL` defaults to `1800` **seconds** and applies to both. `0`
  disables caching; `-1` removes the TTL limit. Other values must be
  nonnegative safe integers.
- Entries expire at the earlier of their original TTL deadline and CRL
  `nextUpdate`. Reading an entry does not extend its lifetime.
- A later caller's shorter TTL also limits the age of an existing entry.
  A longer TTL cannot extend an entry's original expiry.
- The calling request's size limit is applied whenever the shared cache is
  accessed or updated. Reducing the size evicts the least recently used entries.
- Expired entries are removed lazily on cache access and never reused. (In
  the per-certificate cache they stay as refresh candidates, never as answers;
  see [CRL cache scope](#crl-cache-scope).)

With TTL `-1`, CRLs still expire at `nextUpdate` and can be evicted by LRU.
Concurrent misses can download the same CRL independently; cancellation and
policy decisions remain local to each request.

CRL cache options affect only CRLs; OCSP results have their own cache (see
[OCSP caching](#ocsp-caching)).

## Errors and warnings

CRL rejections are `trFetch.TrFetchCrlError` instances; OCSP rejections are
`trFetch.TrFetchOcspError` instances. Both are surfaced directly
instead of being hidden beneath fetch's generic `TypeError: fetch failed`.

| `code` | Policy |
|---|---|
| `TR_FETCH_CRL_MISSING_DISTRIBUTION_POINT` | `missingCrlDistributionPoint` |
| `TR_FETCH_CRL_UNREACHABLE_DISTRIBUTION_POINT` | `unreachableCrlDistributionPoint` |
| `TR_FETCH_CRL_INVALID` | `invalidCrl` |
| `TR_FETCH_CERTIFICATE_REVOKED` | `revokedCertificate` |
| `TR_FETCH_OCSP_MISSING_URI` | `missingOcspUri` |
| `TR_FETCH_OCSP_UNREACHABLE_URI` | `unreachableOcspUri` |
| `TR_FETCH_OCSP_CERTIFICATE_REJECTED` | `rejectedCertificate` |

Messages explain the specific failure. Certificate errors include `policyKey`,
`hostname`, `serialNumber`, `fingerprint256`, and, when applicable,
`distributionPoint` or `ocspUri`, and `cause`. OCSP rejection details include
`ocspStatus`: `'revoked'`, `'unknown'` or `'invalid-response'`.

```js
try {
	await trFetch(url);
} catch (error) {
	if ((error instanceof trFetch.TrFetchCrlError) || (error instanceof trFetch.TrFetchOcspError)) {
		console.error(error.code, error.message);
	} else {
		throw error;
	}
}

process.on('warning', function(warning) {
	if ([ 'TrFetchCrlWarning', 'TrFetchOcspWarning' ].includes(warning.name)) {
		console.error(warning.code, warning.message);
	}
});
```

Warnings use the same codes and context, with the names `TrFetchCrlWarning`
and `TrFetchOcspWarning`. They are Node.js process warnings unless the
`trFetchWarningCb` option is given, in which case each warning goes to that
function instead:

```js
const response = await trFetch(url, {
	trFetchCrlPolicy: { missingCrlDistributionPoint: 'warn' },
	trFetchWarningCb: warning => log.warn({ request: requestId, code: warning.code }, warning.message)
});
```

The callback receives only the warning; context comes with it as a closure,
like `requestId` above. It is purely informational and fire-and-forget: it is
called when the warning arises and never awaited, so it cannot delay, change
or abort the fetch. If it throws or returns a rejected promise, the error is
reported with `console.warn` and otherwise ignored. A value that is not a
function rejects with `TypeError`, and the option is removed before calling
system fetch.

Normal TLS/network failures keep native fetch's error behavior. Cancellation
preserves the caller's abort reason.

## Connection and revocation behavior

An Undici connector performs ordinary Node TLS verification with
`rejectUnauthorized: true`. It then performs the enabled checks before handing
that **same socket** to system fetch. There is no separate TLS probe and no second,
unchecked connection carrying the application request. HTTPS redirect
destinations go through the same checks. HTTP requests have no certificate
to check; standard fetch redirect behavior otherwise applies.

Each fetch call owns an agent. Request sockets and TLS sessions are not reused;
redirects also establish checked connections. This avoids stale revocation
decisions on pooled connections, with extra handshake overhead. Response bodies
remain streamable while the agent closes gracefully after their consumption
or cancellation.

The wrapper retains Node's default CA trust, certificate validity, hostname
verification and TLS settings. It does not install a global dispatcher or
change TLS verification settings. Its Undici dependency may initialize the
normal global dispatcher if one has not yet been created. Explicit custom
dispatchers, custom global dispatchers, and unrecognized dispatcher
configurations are rejected: silently replacing custom trust, pinning or proxy
settings could weaken the application's security. Proxy agents and custom
per-agent TLS configuration are therefore unsupported. Default-dispatcher
recognition inspects Undici configuration and fails closed on unknown layouts.

System fetch drives the package's Undici agent through the dispatcher API of
the Undici version bundled with Node.js. Their major versions must match;
otherwise trFetch rejects with `TypeError` before connecting.

trFetch calls `globalThis.fetch`. Wrappers that pass the `dispatcher` option
on, such as most instrumentation, keep working. If a replacement drops it, the
request is sent over an unchecked connection. trFetch detects this and fails
closed: an HTTP(S) response is accepted only if both the request URL and the
final response URL were reached over connections that its own agent opened and
verified. Otherwise the fetch rejects with `TypeError`, and a CRL or OCSP
download counts as unreachable. The request may already have been sent by then,
so do not replace system fetch with an implementation that ignores
`dispatcher`.

CRL retrieval:

- Accepts only `http:` and `https:` URLs. Files, local paths, LDAP, LDAPS, FTP,
  data URLs and URLs containing credentials are unreachable distribution points.
- Validates every redirect target and uses normal, mandatory TLS verification
  for HTTPS downloads. Download failures use `unreachableCrlDistributionPoint`.
- Does not copy application cookies, authorization headers or request bodies
  into CRL requests.
- Allows at most five redirects, `maxCrlBytes` of decoded response data and ten seconds
  per download including redirects and body reading. Caller cancellation also
  cancels CRL retrieval. At most 32 distribution URIs are tried per certificate.
- Allows private-network HTTP(S) endpoints, including loopback, for private PKI.
  It does not perform filesystem or LDAP lookup.
- Does not recursively check the CRL download server's CRLs or OCSP status.
  Download HTTPS trust is verified normally, and CRL contents must independently
  authenticate under the checked certificate's issuer.

Alternative distribution URIs are tried until a valid, applicable complete CRL
is obtained. Only when all alternatives fail are their failure policies applied.
A successfully authenticated CRL listing the certificate immediately invokes
the revocation policy; it does not trigger a search for a different answer.

Supported CRLs are direct, complete CRLs with SHA-256, SHA-384 or SHA-512
RSA (PKCS #1 v1.5 or PSS) or ECDSA signatures, verified with Node's crypto
module. RSA-PSS must use MGF1 with the signature hash. Validation
checks issuer binding, signature algorithm consistency, `cRLSign` key usage
when present, authority key identifiers when available, dates and scope.
`nextUpdate` is required. Matching named issuing distribution points and
user/CA certificate scopes are supported.

Delta CRLs, indirect CRLs, reason-limited distribution points or CRLs,
attribute-certificate CRLs, unsupported critical extensions and weak or
unsupported signature algorithms use `invalidCrl`. This implementation does
not merge delta CRLs.

### OCSP behavior

The library reads OCSP URIs from the certificate's Authority Information Access
extension and sends a DER request using HTTP POST with
`Content-Type: application/ocsp-request`. Requests contain the certificate's
serial and issuer hashes, with a fresh 32-byte nonce. SHA-1 is used for the
standard issuer identifier; response signatures must use supported SHA-256,
SHA-384 or SHA-512 algorithms.

Only HTTP(S) responder URIs are accepted. Each lookup has a ten-second deadline
and a 1 MiB response limit. HTTP 307/308 redirects preserve the POST body, with
at most five redirects; other redirect codes use `unreachableOcspUri`. Every
redirect URI is validated. Caller cancellation interrupts the lookup. Up to
32 advertised URIs are tried per certificate. Requests contain no application
authorization headers, cookies or body. Private-network HTTP(S) is allowed.

A successful response must contain exactly one matching certificate identifier
and a signature authorized by that certificate's actual issuer. An issuer may
sign directly, or delegate to a certificate it issued directly. A delegated
responder must have OCSP signing extended key usage, digital-signature key usage
when present, current certificate validity, and `id-pkix-ocsp-nocheck`. Delegates
without no-check are currently unsupported because their own revocation status
would require a separate validation path. Weak delegate certificate signatures
and RSA keys shorter than 2048 bits are rejected.

Response `producedAt` and `thisUpdate` must not be in the future. `nextUpdate`,
when present, must not have passed. When it is absent, the response is accepted
for at most five minutes after `thisUpdate`. Signer certificate expiry also
bounds validity. Unknown critical extensions and duplicate or mismatched
certificate identifiers reject. If a responder returns a nonce, it must match
the request; responders that omit it remain subject to the validity-time checks.

Unusable alternatives are tried until an authenticated status is obtained.
An authenticated revoked or unknown status immediately invokes
`rejectedCertificate`; the client does not seek a different answer elsewhere.
Malformed, unsuccessful or unauthenticated responses also use that policy when
no usable alternative exists, with a distinct explanatory message.

OCSP responder HTTPS connections receive normal TLS verification. Their own
revocation endpoints are not recursively queried. This is active OCSP lookup;
TLS-stapled responses are not consumed.

#### OCSP caching

Authenticated `good` and `revoked` results are cached in memory, keyed by the
issuer certificate, the checked certificate and the responder URL. A result is
used until the earlier of the response's `nextUpdate` (itself bounded by the
signer certificate's expiry, and at most five minutes after `thisUpdate` when
the responder gives none) and the TTL. `unknown` statuses, failed lookups and
unusable responses are never cached, so they are asked again every time.
Cached results are looked up before an OCSP request is built; a hit sends no
request.

- `trFetchOcspPolicy.ocspCacheSize` defaults to `1024` results. Any integer
  **0 or less** disables the cache for that call; `null` means the default.
- `trFetchOcspPolicy.ocspCacheTTL` defaults to `1800` **seconds**. It is a
  maximum: a response whose `nextUpdate` is sooner expires then. `0` disables
  caching; `-1` leaves only `nextUpdate`.
- As with CRLs, a later caller's shorter TTL also applies to existing entries,
  and reducing the size evicts the least recently used entries.

A cached response is no fresher than the time it was fetched. Its request
nonce was checked then, and its validity times are the freshness guarantee
afterwards, as for responders that do not echo nonces. Set `ocspCacheTTL: 0`
to query the responder on every connection.

The transport uses Node's documented
[fetch dispatcher interface](https://nodejs.org/api/globals.html#custom-dispatcher)
and [TLS certificate inspection](https://nodejs.org/api/tls.html#tlssocketgetpeercertificatedetailed).
CRL format and scope rules follow the applicable parts of
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280). OCSP verification follows
the applicable parts of [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960).

## tr-curl

The package installs `tr-curl`, a small `curl` replacement built on trFetch.
It is mainly a test tool: every HTTPS connection gets trFetch's CRL and OCSP
checks. Only `http:` and `https:` URLs are supported; a URL without a scheme
defaults to `http://`.

```sh
npx -p tr-fetch tr-curl -v https://example.com/
```

The command is in the `tr-fetch` package, so `npx` needs `-p tr-fetch`.
After `npm install -g tr-fetch`, or inside a project that depends on it,
`tr-curl` can be run directly:

```sh
tr-curl -fsSL -o page.html https://example.com/
tr-curl --json '{"a":1}' -u user:password https://api.example.com/items
tr-curl --cacert private-ca.pem --crlfile current.crl https://internal.example/
```

`tr-curl --help` lists the options. Their meaning follows curl:

| Area | Options |
|---|---|
| Request | `-X/--request`, `-H/--header`, `-A/--user-agent`, `-e/--referer`, `-r/--range`, `--etag-compare`, `-G/--get`, `-I/--head` |
| Data | `-d/--data`, `--data-ascii`, `--data-binary`, `--data-raw`, `--data-urlencode`, `--json` |
| Authentication | `-u/--user`, `--oauth2-bearer`, credentials in the URL |
| Redirects | `-L/--location`, `--location-trusted`, `--max-redirs` |
| Output | `-o/--output`, `-O/--remote-name`, `--remote-name-all`, `--output-dir`, `--create-dirs`, `--remove-on-error`, `-i/--include` |
| Failure and limits | `-f/--fail`, `--fail-with-body`, `--fail-early`, `--max-filesize`, `-m/--max-time` |
| Messages | `-v/--verbose`, `-s/--silent`, `-S/--show-error`, `--no-progress-meter`, `-#/--progress-bar`, `-h/--help`, `-V/--version` |
| TLS | `-k/--insecure`, `--cacert`, `--crlfile`, `-1/--tlsv1`, `--tlsv1.0` … `--tlsv1.3`, `--tls-max`, `--ciphers`, `--tls13-ciphers` |
| trFetch | `--tr-fetch-max-crl-bytes`, `--tr-fetch-crl-cache-scope`, `--tr-fetch-crl-certificate-cache-size`, `--tr-fetch-crl-url`, `--tr-fetch-ocsp-cache-size`, `--tr-fetch-ocsp-cache-ttl`, `--tr-fetch-ocsp-url`, `--tr-fetch-options` |

`--verbose` prints the request and response headers, prefixed with `>` and
`<` like curl, and also enables `trFetchDebug`, so the revocation diagnostics
appear on stderr. `--cacert` replaces Node's default CA certificates for the
process.

The `--tr-fetch-*` options set trFetch options directly:

| Option | trFetch option |
|---|---|
| `--tr-fetch-max-crl-bytes <bytes>` | `trFetchCrlPolicy.maxCrlBytes`, a positive integer |
| `--tr-fetch-crl-cache-scope <crl\|certificate>` | `trFetchCrlPolicy.crlCacheScope`; tr-curl's default is `certificate` |
| `--tr-fetch-crl-certificate-cache-size <count>` | `trFetchCrlPolicy.crlCertificateCacheSize`, an integer |
| `--tr-fetch-crl-url <url>` | `trFetchCrlDistributionPointOverride` |
| `--tr-fetch-ocsp-cache-size <count>` | `trFetchOcspPolicy.ocspCacheSize`, an integer |
| `--tr-fetch-ocsp-cache-ttl <seconds>` | `trFetchOcspPolicy.ocspCacheTTL`, `-1` or more |
| `--tr-fetch-ocsp-url <url>` | `trFetchOcspUriOverride` |
| `--crlfile <file>` | `trFetchCrlOverride`, read from the file |

`--tr-fetch-options` takes a JSON object of any trFetch options, for example
`'{"trFetchCrlPolicy":{"crlCheckDepth":"full-chain"}}'`. It can be repeated;
later objects replace earlier keys. The options above take precedence over the
same settings in it, whatever their order, and the CRL and OCSP cache and size
options are merged into its `trFetchCrlPolicy` and `trFetchOcspPolicy` rather
than replacing them.

`--insecure` cannot be implemented through trFetch, which never relaxes TLS
verification. With `-k`, tr-curl uses plain fetch with an unverified TLS
connection instead, so no CRL or OCSP checks are made.

Exit codes follow curl, for example: 1 unsupported protocol, 2 usage error,
3 malformed URL, 6 unresolvable host, 7 connection failure, 18 partial
transfer, 22 HTTP error with `--fail`, 23 write error, 28 timeout, 35 TLS
handshake failure, 47 too many redirects, 60 certificate verification failure
or CRL rejection, 63 maximum file size exceeded, and 91 OCSP rejection.

Differences from curl:

- Options are parsed with [Optist](https://www.npmjs.com/package/optist).
  `--name=value` is accepted, short options that take an argument cannot be
  combined with other short options (`-o file`, not `-ofile`), and single-value
  options may be given only once. Options may follow URLs, and `--` ends
  option parsing.
- The `-o` and `-O` options cannot be mixed. `-o` names pair with URLs in
  order, and `-O` applies to as many URLs as it is given.
- Requests use HTTP/1.1 through fetch. Fetch sets `Host`, `Connection` and
  `Content-Length` itself, adds `Accept-Language`, `Sec-Fetch-Mode` and
  `Accept-Encoding`, and decodes compressed responses. `-H "Name:"` removes
  only headers that tr-curl itself would add. Response header names appear in
  lowercase.
- TLS-SRP (`--tlsuser`, `--tlspassword`, `--tlsauthtype`) and other TLS
  backend features that Node.js does not provide are not supported. URL
  globbing, cookies, proxies, uploads and non-HTTP protocols are not
  implemented either.

## Development

```sh
npm install
npm test
```

Enable fetch diagnostics during tests with:

```sh
TR_FETCH_TEST_DEBUG=yes npm test
```

`TR_FETCH_TEST_DEBUG` accepts `y`, `yes`, `true` or `1`, case-insensitively.
Other values (or an unset variable) leave test debugging off. This sets
`trFetchDebug: true` by default for test fetch calls; explicit options in tests
that verify debugging behavior still take precedence. The variable affects
only the test suite, not the library's runtime defaults.

Tests use Node's built-in test runner and generate temporary signing keys,
certificates, CRLs and OCSP responses in memory. Integration tests run local
HTTP/HTTPS servers; they do not require public network access.

Runtime dependencies: `undici` for the transport adapter, `pkijs` and `asn1js`
for X.509/CRL/OCSP parsing and signature verification, and `optist` for
tr-curl's command line. No compiler or external OpenSSL executable is required.
