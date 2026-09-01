# Security policy

This engine decides whether a person holding a **national eID card** is who the card says they are,
and it drives the card through a **signing operation**. It validates a Web eID authentication token —
token signature, certificate chain against trusted CA material, revocation over OCSP, the site-origin
binding, and single use of a challenge nonce — and it prepares and finalises card-based signatures.

It is deliberately thin: the cryptography lives in the `go-web-eid` library, and this service is the
process that runs it — inbound service authentication, trust material, revocation policy, audit, and
the wiring that decides how strictly the library's checks are applied.

So the failures that matter most are **acceptances that should have been refusals**. A forged,
replayed or wrong-origin token that authenticates someone; a revoked or untrusted certificate that
passes; a signature produced under an identity other than the one that authenticated.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/go-make-bytes/web-eid/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs, if it only appears under particular settings — several checks here are
  opt-in or policy-driven, so the wiring matters as much as the code;
- whether you have told anyone else, and whether a disclosure date already binds you.

**Please do not send us real cards, real certificates, real authentication tokens or national
identifiers.** A redacted trace, a test certificate, or the shape of the value explains almost any
finding here.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

**Authenticating someone who should not have been authenticated.**

- A challenge nonce that can be replayed, guessed, used twice, or used after it expired — or one
  that is not bound to the browser session that was issued it. It is removed as it is read, on
  purpose.
- An authentication token accepted for an origin other than the configured one, or a way past the
  origin binding — this is the check that stops a token harvested by another site from working here.
- A certificate chain accepted that does not anchor in the configured trusted CA material, or trust
  material that can be influenced from outside the operator's control — including through the
  managed trust-bundle sync, which writes into the same directory the validator reads.
- **Revocation that fails open.** A revoked certificate must fail. An OCSP response accepted without
  a verified signature, past its freshness bounds, with an unmatched nonce, or from a responder the
  allowlist does not name, is a serious finding — as is any path that treats an OCSP failure as a
  pass.

**Signing under the wrong identity, or with the wrong bytes.**

- The authentication and signing certificates not being confirmed to belong to the same natural
  person on a verified finalise. A mismatch fails; a binding that is skipped must be *reported*, not
  silently treated as satisfied.
- A signature value accepted whose encoding does not match the negotiated algorithm — ECDSA must be
  the raw P1363 pair of the curve's exact length, RSA verified per the negotiated scheme, and the
  digest length must match the named hash. A guessed or coerced re-encoding is a signature nobody
  authorised in that form.
- A signing certificate accepted without the required policy assertion, or one bearing a denied
  policy arc — the gate that keeps a non-qualified or masquerading certificate out.

**Reaching the engine at all.** Every route except the liveness and readiness probes is behind
DPoP-bound inbound service authentication. Reaching an authentication or signing route without a
valid token, with a token bound to a different key, or with a scope the route does not require, is a
finding.

**Personal data.** The eID national identifier is pseudonymised with an HMAC before any access
record leaves the process, and nothing from the certificate is persisted. A national identifier
appearing raw in a log line, an error body, a response or an audit record is a finding; so is the
pseudonym key reaching any of those.

**Configuration that degrades a check silently.** Start-up is fail-closed on bad trust material, an
invalid engine configuration, or a missing pseudonym key when access auditing is on. A configuration
hole that boots anyway — or that quietly disables revocation, origin enforcement or the policy gate —
is how a weakened deployment reaches production unnoticed.

Denial of service and findings that need an already-compromised host or an already-authenticated
administrator are in scope but lower priority. Reports about outdated dependencies are welcome
where you can show the vulnerable path is actually reachable.

## What is deliberately not a finding

This engine has **no browser-facing surface**. The browser talks to the unmodified Web eID client
stack and to the calling service; nothing here is reachable from a page. A report that assumes a
direct browser path to these routes is describing a deployment mistake rather than a defect here.

It also **issues no cards, runs no QTSP, and assembles no signature container**. It returns the
card's signed value and the certificate; building and validating the container is the caller's job.

The **cryptography itself lives in the `go-web-eid` library**, which is public and has its own
repository — a flaw in that code is best reported there. What is a finding *here* is this service
mis-wiring it: a check left off by default that should be on, a strictness the engine relaxes, a
guarantee the library offers that this process does not actually take up.

Two documented limitations are not vulnerabilities in themselves, though a concrete exploitation of
either is: the cookie-session login flow keeps its nonce in process memory and so is single-instance,
and revocation is OCSP-only with no CRL fallback, with the responder allowlist empty by default.

## Scope

This policy covers the code in this repository. It does not cover the `go-web-eid` library, the Web
eID browser extension or native application, the trust-anchor service, the card issuer, or any
deployment operated by someone other than us — report those to the parties that run them. How a
deployment configures this engine is the operator's responsibility, but a report that a **default**
is unsafe is very much in scope, and several of the defaults here are deliberately conservative for
that reason.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
