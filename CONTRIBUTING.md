# Contributing

Thank you for considering a contribution. Bug reports, fixes and improvements are welcome. For
anything that could be exploited, use the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

For anything larger than a small fix, please open an issue first and describe what you want to
change and why. This engine decides whether a card presentation authenticates a person, so most of
its behaviour is a refusal waiting to happen, and a change that fights that design is better
redirected before it is written than after.

## Building and testing

You need the Go toolchain at the version named in [go.mod](go.mod). Every dependency is public, so
nothing needs credentials, a `GOPRIVATE` setting or a vendor directory. The gate a change must pass
is the same one CI runs:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

Three more checks run in CI and are worth running before you push:

- **Lint** — `golangci-lint run`, at the version pinned in
  [.github/workflows/ci.yml](.github/workflows/ci.yml); the repo's [.golangci.yml](.golangci.yml)
  carries the configuration.
- **Vulnerabilities** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.
- **The image** — CI builds it, generates an SBOM, fails on HIGH/CRITICAL findings from a
  vulnerability scan, and signs it. A change to the [Dockerfile](Dockerfile) should be built
  locally before you push, because that job is slow to fail.

The committed tree must already be tidy: CI runs `go mod tidy -diff` and fails if it would change
anything, so run `go mod tidy` after touching dependencies. All Go code is `gofmt`-formatted, and
`.gitattributes` pins Go files to LF line endings — leave that alone, it keeps the tidy-diff gate
stable across platforms.

Tests need no card, no reader and no network: the trust material under `testdata/` and in-process
fakes stand in for the card stack, the trust-anchor service and the audit sink. If a change makes a
test need a real card or a live upstream, that is a design signal worth raising in the issue rather
than solving with a fixture.

## What a change to this service needs

Read the **Security invariants** section of the [README](README.md) before changing anything on the
authentication or signing path. They are not documentation of good intentions; each one is the
reason a specific class of defect cannot happen.

The three that carry the most weight:

- **Every check fails closed, and revocation most of all.** A revoked certificate fails; an OCSP
  response is accepted only with a verified signature, inside its freshness bounds, with its nonce
  matched where the responder supports one. Turning any failure — a timeout, an unreachable
  responder, an unparseable response — into a pass is the change, not a side effect of one. The same
  applies at start-up: bad trust material, an invalid engine configuration or a missing pseudonym
  key stop the process rather than degrading it.
- **The nonce is single-use, and the origin binding is not advisory.** The challenge is removed as
  it is read, bounded by a TTL and tied to the browser session that received it; the token is
  verified against the configured origin. These two together are what stop a replayed or harvested
  token. A change anywhere near them needs a test that fails if the guard is removed.
- **Identity binding on a verified finalise is a refusal, not a warning.** The authentication and
  signing certificates must belong to the same natural person; a mismatch fails the request, and a
  binding that was *skipped* is reported as skipped rather than reported as satisfied. The
  difference between those two is the whole value of the check.

Also load-bearing:

- **Signature encoding is validated exactly.** ECDSA values are the raw fixed-width pair of the
  curve's expected length; RSA is verified per the negotiated scheme; the digest length must match
  the named hash. Never guess, never re-encode on a best effort.
- **The policy gate keeps non-qualified certificates out.** Accepted policy assertions and the
  denied arcs are a security decision, not configuration trivia.
- **No personal data is persisted, and none is logged raw.** The national identifier is
  pseudonymised with an HMAC before any access record leaves the process; security telemetry is
  metadata only. The pseudonym key is an operator secret and belongs nowhere near a log or a store.
- **The engine has no browser-facing surface.** Callers reach it server-to-server with a DPoP-bound
  service token, and only the liveness and readiness probes are public. A new route is behind that
  middleware or it is a design discussion first.
- **The cryptography belongs to the library.** This service wraps `go-web-eid`; a fix that
  reimplements a check here instead of in the library splits one guarantee across two places. If the
  library needs to change, change it there.

## Proposing a change

- Work on a branch and open a pull request against `develop`. `develop` is merged into `main` and
  tagged there when a release goes out, so `main` is never committed to directly.
- **Sign off every commit.** This project uses the
  [Developer Certificate of Origin](https://developercertificate.org/): by adding a
  `Signed-off-by: Your Name <you@example.org>` line you certify that you wrote the change or
  otherwise have the right to submit it under this project's licence. `git commit -s` adds the line
  for you; the name and address must match the commit author. A pull request whose commits lack it
  fails the DCO check and cannot be merged.
- Keep the change focused: one concern per pull request.
- A change in behaviour comes with a test that fails without it.
- Match the style around you — naming, error handling, comment density. Comments explain what and
  why in plain domain terms; a reference to a standard is cited in the bracket form already used in
  the code.
- A change an operator or an integrator can feel — a new or changed endpoint, field, error code,
  configuration knob or default — belongs in [CHANGELOG.md](CHANGELOG.md) in the same pull request.
- Pull requests also run a dependency review. A new dependency needs a reason the standard library
  or the existing ones cannot cover.

## Licence

This project is licensed under the **MIT licence** (see [LICENSE](LICENSE)). By submitting a
contribution you agree that it is provided under the same licence — you keep the copyright in what
you wrote, and everyone, including commercial users, may use it under MIT's terms.
