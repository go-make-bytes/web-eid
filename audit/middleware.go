package audit

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-web-eid/certificate"
)

// Endpoint path suffixes the middleware acts on.
const (
	pathLogin    = "/auth/login"
	pathValidate = "/auth/validate"
	pathSignCert = "/sign/certificate"
	pathFinalize = "/sign/finalize"
)

// Middleware returns an azugo middleware that records audit events for the
// go-web-eid engine endpoints, without modifying the library. It runs AFTER the
// inbound go-authbyte middleware (so the authenticated caller is known) and
// wraps the library handlers: it captures the caller, runs the handler, then
// emits a NIS2-audit security event from the outcome and — on success — a GDPR-audit
// personal-data-access record with a pseudonymized subject.
func (r *Recorder) Middleware() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			path := ctx.Path()
			kind := endpointKind(path)
			if kind == "" {
				next(ctx)

				return
			}

			caller := authorizedID(ctx)

			next(ctx)

			status := ctx.Response().StatusCode()
			success := status >= 200 && status < 300

			switch kind {
			case pathLogin, pathValidate:
				r.AuthValidated(ctx, caller, success, status)
				if success {
					// The login handler set the validated eID subject as the user.
					if subj := authorizedID(ctx); subj != "" && subj != caller {
						r.IdentityValidated(ctx, caller, subj)
					}
				}
			case pathSignCert:
				r.SigningCertificate(ctx, caller, success, status)
				if success {
					r.SigningCertAccessed(ctx, caller, reqCertSubject(ctx, "certificate"))
				}
			case pathFinalize:
				r.Finalize(ctx, caller, success, status, finalizeIdentityBound(ctx))
				if success {
					r.FinalizeCertAccessed(ctx, caller, reqCertSubject(ctx, "signingCertificate", "authCertificate"))
				}
			}
		}
	}
}

// endpointKind returns the matched endpoint suffix, or "" to skip (challenge,
// jwks, anything else).
func endpointKind(path string) string {
	switch {
	case strings.HasSuffix(path, pathLogin):
		return pathLogin
	case strings.HasSuffix(path, pathValidate):
		return pathValidate
	case strings.HasSuffix(path, pathSignCert):
		return pathSignCert
	case strings.HasSuffix(path, pathFinalize):
		return pathFinalize
	default:
		return ""
	}
}

// authorizedID returns the authenticated principal's id, or "".
func authorizedID(ctx *azugo.Context) string {
	u := ctx.User()
	if u == nil || !u.Authorized() {
		return ""
	}

	return u.ID()
}

// reqCertSubject extracts the eID national identifier from the first present
// base64-DER certificate field in the request body, or "" when none can be
// parsed. The raw id is returned for pseudonymization by the caller; it is never
// logged itself.
func reqCertSubject(ctx *azugo.Context, fields ...string) string {
	body := ctx.Body.Bytes()
	if len(body) == 0 {
		return ""
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}

	for _, f := range fields {
		var b64 string
		if msg, ok := raw[f]; ok {
			if json.Unmarshal(msg, &b64) != nil || b64 == "" {
				continue
			}
			if id := idCodeFromB64Cert(b64); id != "" {
				return id
			}
		}
	}

	return ""
}

// idCodeFromB64Cert parses a base64-DER certificate and returns its eID national
// identifier (SubjectIDCode), or "".
func idCodeFromB64Cert(b64 string) string {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}

	id, err := certificate.SubjectIDCode(cert)
	if err != nil {
		return ""
	}

	return id
}

// finalizeIdentityBound reads the IdentityBound flag from the finalize response
// body (best effort; false when unavailable).
func finalizeIdentityBound(ctx *azugo.Context) bool {
	var resp struct {
		IdentityBound bool `json:"identityBound"`
	}
	if json.Unmarshal(ctx.Response().Body(), &resp) != nil {
		return false
	}

	return resp.IdentityBound
}
