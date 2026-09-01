// Package webeid is the eSignature-Portal Web eID engine service: a thin Azugo
// deployable that wraps the github.com/gmb-lib/go-web-eid library and exposes
// its authentication-token validation and eID-card signing-operation endpoints
// behind go-authbyte service authentication.
//
// The engine has no browser-facing surface. The SPA talks to the Auth Service;
// the Auth Service (login) and the CSC signing service (card-ops) call this
// engine server-to-server with a DPoP service token (proposal v3: stateless
// eID engine, sidecar by default). All cross-cutting concerns — logging,
// correlation, metrics — come from go-platform-kit's platform.Setup.
package webeid

import (
	"fmt"
	"time"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/observability"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/gmb-lib/go-sec-events/secevents"
	webeidazugo "github.com/gmb-lib/go-web-eid/azugo"
	"github.com/go-make-bytes/web-eid/audit"
	"github.com/go-make-bytes/web-eid/trustsync"
)

// App is the web-eid engine application container.
type App struct {
	*azugo.App

	config *Configuration

	webeid     *webeidazugo.Handler
	authClient *authclient.Client
	authMW     azugo.RequestHandlerFunc

	// Audit: NIS2-audit always; GDPR-audit gdpr client + its outbound auth-client are
	// set only when access-audit is configured.
	auditClient *authclient.Client
	gdprAudit   *gdpr.Client
	audit       *audit.Recorder

	// Trust-bundle sync state (nil / zero when the sync is not configured);
	// read by the /v1/trust-status diagnostic route.
	trustSync      *trustsync.Syncer
	trustSyncEvery time.Duration
}

// New creates the application: configuration, platform cross-cutting setup, the
// Web eID engine handler (validator + nonce generator + signer, with trusted CA
// material loaded) and the inbound service-authentication middleware.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Web eID Engine",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}
	return app, nil
}

func (a *App) init() error {
	cfg := a.config

	if err := platform.Setup(a.App, platform.Options{
		Config: cfg.BaseConfiguration,
	}); err != nil {
		return err
	}

	// Inject an otel-instrumented transport for OCSP responder calls so they
	// show as client spans (only used when WEBEID_OCSP_ENABLED=true). The library
	// stays dependency-pure — it takes a stdlib RoundTripper.
	engineOpts := []webeidazugo.Option{webeidazugo.WithOCSPTransport(observability.InstrumentedTransport(nil))}
	if cfg.TrustAnchorURL != "" {
		// Trust material is runtime-managed: the sync below fills the trust
		// directory and reloads the engine, so an empty directory at boot is a
		// valid starting state (first boot on a fresh volume), not a fatal
		// misconfiguration. Without the sync the default stays fail-at-start.
		engineOpts = append(engineOpts, webeidazugo.WithRuntimeTrust())
	}
	h, err := webeidazugo.New(cfg.WebEID, engineOpts...)
	if err != nil {
		return fmt.Errorf("web-eid: engine: %w", err)
	}
	a.webeid = h

	a.authClient, err = authclient.New(cfg.Auth)
	if err != nil {
		return fmt.Errorf("web-eid: auth client: %w", err)
	}
	a.authMW = a.authClient.Authenticate()

	// Audit emitters. NIS2-audit (NIS2 security telemetry) always emits via the log
	// sink → SIEM. GDPR-audit (GDPR personal-data access) is wired only when
	// access-audit is configured: the engine processes eID certificate PII, so it
	// records each validated/processed identity as a personal-data access, with a
	// PSEUDONYMIZED subject ref (raw national id is never logged).
	secEmitter := secevents.NewEmitter(secevents.NewLogSink())

	var (
		psn *audit.Pseudonymizer
		gc  *gdpr.Client
	)
	if cfg.AccessAuditEnabled() {
		psn, err = audit.NewPseudonymizer(cfg.PseudonymKeyBytes())
		if err != nil {
			return fmt.Errorf("web-eid: audit pseudonym key (set AUDIT_SUBJECT_PSEUDONYM_KEY when ACCESS_AUDIT_URL is set): %w", err)
		}

		oc, err := authclient.New(cfg.ServiceAuthClientConfig())
		if err != nil {
			return fmt.Errorf("web-eid: audit auth client: %w", err)
		}
		a.auditClient = oc

		var outbox gdpr.Outbox
		if dir := cfg.AccessAuditOutboxDir; dir != "" {
			ob, err := gdpr.NewFileOutbox(dir, gdpr.DefaultOutboxCapacity)
			if err != nil {
				return fmt.Errorf("web-eid: audit outbox: %w", err)
			}
			outbox = ob
		}

		gc, err = gdpr.New(
			cfg.GDPRConfig(),
			newAccessAuditPoster(oc, cfg.AccessAuditURL, cfg.AccessAuditAudience, cfg.AccessAuditScope),
			gdpr.Options{Outbox: outbox, Logger: a.Log()},
		)
		if err != nil {
			return fmt.Errorf("web-eid: gdpr-audit client: %w", err)
		}
		a.gdprAudit = gc

		if err := a.AddTask(audit.NewDrainTask(gc)); err != nil {
			return fmt.Errorf("web-eid: gdpr drain task: %w", err)
		}
	} else {
		a.Log().Warn("ACCESS_AUDIT_URL not set — GDPR (GDPR-audit) access records will NOT be posted (development); NIS2-audit security telemetry still emits")
	}

	a.audit = audit.New(secEmitter, gc, psn, a.Log())

	// Trust-bundle sync (P5b, Mode A): when configured, fetch trust-anchor's
	// /v1/anchors on startup + interval and maintain a managed PEM file in the
	// library's trust directory. Opt-in: empty TrustAnchorURL disables it.
	if cfg.TrustAnchorURL != "" {
		// Trust-sync mints a DPoP service token at the Auth /token endpoint, so it
		// needs the OUTBOUND auth-client config (in-network issuer override via
		// AUTH_OUTBOUND_ISSUER_URL + this engine's service-client creds) — NOT
		// a.authClient, whose IssuerURL is the public issuer used for INBOUND
		// validation and is unreachable from inside the cluster (would dial e.g.
		// https://localhost:5001). ServiceAuthClientConfig is the single outbound
		// config shared by trust-sync and the audit poster, independent of whether
		// GDPR-audit (audit) is enabled.
		tsClient, err := authclient.New(cfg.ServiceAuthClientConfig())
		if err != nil {
			return fmt.Errorf("web-eid: trust-sync auth client: %w", err)
		}
		syncer := trustsync.New(tsClient, trustsync.Options{
			AnchorsURL:  cfg.TrustAnchorURL,
			Audience:    cfg.TrustAnchorAudience,
			Scope:       cfg.TrustAnchorScope,
			DestDir:     cfg.TrustSyncDir,
			ManagedName: "00-trust-anchor.pem",
			Log:         a.Log(),
			// A written bundle must be the one the next validation uses:
			// reload the engine's trusted set from the directory on every
			// fresh bundle, so a newly listed issuer's cards work without a
			// restart (and a first boot on an empty directory heals on the
			// first successful pull).
			OnChange: func() error {
				n, err := h.ReloadTrust()
				if err != nil {
					return err
				}
				a.Log().Info("trust anchors reloaded into the running engine",
					zap.Int("certificates", n))
				return nil
			},
		})
		if err := a.AddTask(trustsync.NewTask(a.App, syncer, cfg.TrustSyncInterval)); err != nil {
			return fmt.Errorf("web-eid: trust sync task: %w", err)
		}
		a.trustSync = syncer
		a.trustSyncEvery = cfg.TrustSyncInterval
		if a.trustSyncEvery <= 0 {
			a.trustSyncEvery = time.Hour // the task applies the same default
		}
	}

	return nil
}

// Config returns the loaded configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}
	return a.config
}

// WebEID returns the Web eID engine handler.
func (a *App) WebEID() *webeidazugo.Handler { return a.webeid }

// Audit returns the audit recorder (NIS2-audit always; GDPR-audit when configured).
func (a *App) Audit() *audit.Recorder { return a.audit }

// TrustSync returns the trust-bundle syncer (nil when the sync is not
// configured) and its effective interval.
func (a *App) TrustSync() (*trustsync.Syncer, time.Duration) {
	return a.trustSync, a.trustSyncEvery
}

// AuthMiddleware returns the inbound service-authentication middleware.
func (a *App) AuthMiddleware() azugo.RequestHandlerFunc { return a.authMW }

// SetAuthMiddleware overrides the inbound authentication middleware. Test use
// only — production wiring always uses the go-authbyte DPoP middleware.
func (a *App) SetAuthMiddleware(mw azugo.RequestHandlerFunc) { a.authMW = mw }
