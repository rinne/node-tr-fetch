# Changelog

## 1.1.0 (2026-10-21)

- OCSP responses may now have a `thisUpdate` (and `producedAt`) up to
  `trFetchOcspPolicy.ocspThisUpdateMaxClockSkew` seconds in the future,
  `900` (15 minutes) by default. Some major CAs serve responses through CDNs
  whose clocks run ahead, and 1.0.x rejected those responses. Set `0` for the
  earlier strict check.
- New `trFetchOcspPolicy.ocspNextUpdateMaxClockSkew` (default `0`, strict)
  accepts responses for that many seconds after their `nextUpdate`. It is
  non-standard, so a positive value emits a `TrFetchOcspWarning` with the
  code `TR_FETCH_OCSP_NONSTANDARD_VALIDATION` on every call.
- Both take `0` to `86400` seconds. They never extend a cached result
  beyond the response's own `nextUpdate`.
- New `tr-curl` options `--tr-fetch-ocsp-this-update-max-clock-skew` and
  `--tr-fetch-ocsp-next-update-max-clock-skew`.

## 1.0.1 (2026-10-17)

- Fixed every fetch failing with "trFetch requires the default Undici
  dispatcher" when Undici 8.12 or later is installed. Undici 8.12 stores its
  new `tls` option as `undefined` in every Agent, and trFetch did not
  recognize the default dispatcher with it. Options stored as `undefined`
  now count as not configured; a dispatcher with any configured option is
  still rejected.

## 1.0.0 (2026-09-28)

First stable release. The API is feature complete, and from this release on
its options, policy settings, error classes and codes, and `tr-curl` options
follow semantic versioning.

- `trFetch()`: Node.js `fetch()` with certificate revocation checking by CRL
  and OCSP, done on the same verified TLS connection that carries the request.
- CRL checking of the server certificate or the whole chain, streamed or
  downloaded and indexed, with a size limit, caching, and overrides.
- OCSP checking with authenticated responses, delegated responders and
  result caching.
- A revocation strategy (`ocsp-first` by default, `crl-first` or `both`) and
  an optional requirement that some check establishes each certificate's
  status.
- Per-condition policies (`ignore`, `warn` or `reject`), warnings to a
  callback or as process warnings, and debug diagnostics.
- `tr-curl`, a curl-like command line tool built on trFetch.
- Requires Node.js 26 or later.

Earlier 0.9.x releases were development versions and are not listed here.
See [README.md](README.md) for the documentation.
