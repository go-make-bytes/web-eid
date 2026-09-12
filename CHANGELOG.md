# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.1

### Fixed — a version tag points at the signed image digest again

Publishing a release re-pointed the version tag by rewrapping the image manifest into a new
manifest list, which gave the tag a **different digest from the one the signature covers** — so
verifying the signature on a version tag failed. The retag is now a plain pull, tag and push, which
keeps the digest and therefore keeps the signature valid. Separately, a release published right
after a merge could race the branch build; the job now waits for the image to be published before
tagging.

**A version tag published before this needs one release re-publish** to be re-pointed at the signed
digest. Verifying the rolling `:develop` or `:latest` tag was never affected.

### Changed — the metrics endpoint no longer offers OpenMetrics

A scraper that asked for the OpenMetrics format by sending `Accept: application/openmetrics-text`
used to be answered in it, with the `# EOF` terminator that format requires. This service now
answers in the Prometheus text format whatever the scraper asks for, and writes no `# EOF`:

```http
GET /metrics
Accept: application/openmetrics-text

200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

**The metric names, labels and values are unchanged**, so Prometheus — and anything else that
accepts the plain-text exposition format — needs nothing done. Two setups need a look: a scrape
configuration that *requires* the OpenMetrics content type, and a check that reads a missing
`# EOF` as a truncated scrape. Both need their expectation relaxed.

The endpoint itself is unchanged otherwise: still `/metrics` (or `METRICS_PATH`), still enabled by
default, and still answered only for trusted addresses (`METRICS_TRUSTED_IPS`, `127.0.0.1` by
default) — so if nothing scrapes this service, there is nothing to do. The change arrives from the
web framework this service is built on rather than from a change of its own, carried in with the
shared libraries below.

### Notes

- The shared libraries moved to their current releases — the auth client at v0.21.0 and the
  platform kit at v1.11.2 — which carried the web framework, the HTTP stack and the JOSE library up
  with them. No endpoint, field, error or setting of this service changed, and no configuration
  needs touching. The move also clears two published advisories in the cryptography library this
  service depends on; a third has no fix available yet and was already present before the move, and
  the vulnerability scanner reports nothing this service's own code can reach.

### Changed — the shared libraries move to their current releases

`go-platform-kit` v1.11.3, `go-authbyte` v0.23.1, `go-web-eid` v0.15.4, `go-gdpr-audit` v1.1.5 and
`go-sec-events` v1.2.1. No endpoint, field, error or setting changes with them, nothing in your
configuration needs touching, and this service's own behaviour is unchanged — token validation,
certificate checks and the OCSP path all behave exactly as before, and the OCSP parsing code in
`go-web-eid` is byte-identical across its own dependency move. Two crossed releases are worth
naming: `go-authbyte` v0.23.0 added a way to tell a natural person's identity code from an
organisation's, and `go-sec-events` v1.2.0 allows a security event to be emitted from work with no
request behind it. Both are additions to the libraries.

## v0.1.0

Initial code.

The Web eID engine service as first released: validates the Web eID authentication token an
eID smart card produces — token signature, certificate chain against trusted CA material,
OCSP revocation, site-origin binding, single-use challenge nonce — and prepares and finalizes
card-based signing (algorithm/hash negotiation, raw signature return and optional verify),
behind inbound service authentication, with a trust bundle synced from the platform's
trust-anchor service. MIT.
