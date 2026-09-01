// Package routes registers the web-eid engine HTTP API.
package routes

import (
	webeid "github.com/go-make-bytes/web-eid"
)

type router struct {
	*webeid.App
}

// Init registers all routes: public liveness/readiness probes plus the Web eID
// engine endpoints (/auth/challenge, /auth/login, /sign/certificate,
// /sign/finalize) gated behind inbound service authentication.
//
// The engine has no browser-facing surface — callers reach it server-to-server
// with a DPoP service token (the Auth Service for login, the CSC signing
// service for card-ops), so the whole mounted surface sits behind the
// go-authbyte middleware. Health probes stay public for k8s
// and the `web-eid health` command.
func Init(a *webeid.App) error {
	r := &router{App: a}

	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	// Trust-identity diagnostics: same inbound service auth as the engine
	// surface, but outside the audit wrapper — no personal data and no card
	// operation to record.
	diag := a.Group("/v1")
	diag.Use(a.AuthMiddleware())
	diag.Get("/trust-status", r.trustStatus)

	secured := a.Group("")
	secured.Use(a.AuthMiddleware())
	// Audit middleware runs after inbound auth (so the caller is known) and wraps
	// the library handlers to emit NIS2-audit security events + GDPR-audit access
	// records from each operation's outcome.
	secured.Use(a.Audit().Middleware())
	if err := a.WebEID().Bind(secured); err != nil {
		return err
	}

	return nil
}
