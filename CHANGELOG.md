# Changelog

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
