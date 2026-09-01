# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0

Initial code.

The Web eID engine service as first released: validates the Web eID authentication token an
eID smart card produces — token signature, certificate chain against trusted CA material,
OCSP revocation, site-origin binding, single-use challenge nonce — and prepares and finalizes
card-based signing (algorithm/hash negotiation, raw signature return and optional verify),
behind inbound service authentication, with a trust bundle synced from the platform's
trust-anchor service. MIT.
