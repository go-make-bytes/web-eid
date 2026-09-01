// Package audit records the Web eID engine's audit events through the platform
// emitter libraries:
//
// - NIS2-audit (NIS2 security telemetry) via go-sec-events → SIEM: auth-token
// validation and signing-certificate / finalize outcomes (success/failure),
// metadata only (the authenticated caller as actor, the endpoint, a coarse
// outcome category — never the eID holder's PII).
// - GDPR-audit (GDPR personal-data access) via go-gdpr-audit → access-audit: the
// engine processes a person's eID certificate(s) — full name, national ID,
// certificate details — on both login and signing, so each successful
// operation is a personal-data access. The data-subject reference is a
// PSEUDONYM (HMAC-SHA256 of the national ID); the raw national ID, names and
// certificate details are NEVER written to the access log.
//
// GDPR-audit is OPTIONAL — when access-audit is not configured the engine still
// emits NIS2-audit. The events are produced by an engine-layer Middleware that
// wraps the go-web-eid handlers, so the library stays untouched.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
)

// Engine security event types. Login reuses the canonical
// go-sec-events type; the signing endpoints use engine-specific types.
const (
	eventSigningCertificate = "webeid.signing_certificate"
	eventFinalize           = "webeid.finalize"
)

// Engine GDPR-audit event types.
const (
	eventIdentityValidated  = "webeid.identity_validated"  // /auth/login
	eventSigningCertAccess  = "webeid.signing_cert_access" // /sign/certificate
	eventFinalizeCertAccess = "webeid.finalize_cert_access"
)

// Pseudonymizer turns an eID national identifier into a stable, non-reversible
// reference for the access log. The key is held in memory only (from Vault).
type Pseudonymizer struct {
	key []byte
}

// NewPseudonymizer returns a Pseudonymizer over a copy of key. key must be
// non-empty.
func NewPseudonymizer(key []byte) (*Pseudonymizer, error) {
	if len(key) == 0 {
		return nil, errors.New("audit: empty pseudonym key")
	}

	k := make([]byte, len(key))
	copy(k, key)

	return &Pseudonymizer{key: k}, nil
}

// Ref returns the pseudonymous data-subject reference for an eID national id
// (e.g. "PNOLV-XXXXXX-XXXXX"), or "" when id is empty. It is the hex HMAC-SHA256
// of the id — stable per deployment, never reversible to the id.
func (p *Pseudonymizer) Ref(id string) string {
	if p == nil || id == "" {
		return ""
	}

	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write([]byte(id))

	return "psn:" + hex.EncodeToString(mac.Sum(nil))
}

// Recorder emits the engine's NIS2-audit security events and GDPR-audit
// personal-data-access records. It is safe for concurrent use.
type Recorder struct {
	sec  *secevents.Emitter
	gdpr *gdpr.Client // optional; nil when access-audit is not configured
	psn  *Pseudonymizer
	log  *zap.Logger
}

// New builds a Recorder. sec is required (NIS2-audit always emits); gdprClient and
// psn may be nil together (GDPR-audit then no-ops).
func New(sec *secevents.Emitter, gdprClient *gdpr.Client, psn *Pseudonymizer, log *zap.Logger) *Recorder {
	if log == nil {
		log = zap.NewNop()
	}

	return &Recorder{sec: sec, gdpr: gdprClient, psn: psn, log: log}
}

// ---- NIS2-audit — security telemetry (go-sec-events → SIEM) -------------------

// AuthValidated records the outcome of an eID auth-token validation
// (/auth/login). caller is the authenticated service that invoked the engine.
func (r *Recorder) AuthValidated(ctx *azugo.Context, caller string, success bool, status int) {
	r.emit(ctx, secevents.EventAuthentication, caller, success, status, map[string]any{
		secevents.AttrMethod: "web-eid",
	})
}

// SigningCertificate records the outcome of /sign/certificate validation.
func (r *Recorder) SigningCertificate(ctx *azugo.Context, caller string, success bool, status int) {
	r.emit(ctx, eventSigningCertificate, caller, success, status, nil)
}

// Finalize records the outcome of /sign/finalize. identityBound reports the
// auth↔signing same-natural-person check (only meaningful on success).
func (r *Recorder) Finalize(ctx *azugo.Context, caller string, success bool, status int, identityBound bool) {
	attrs := map[string]any{}
	if success {
		attrs["identity_bound"] = identityBound
	}
	r.emit(ctx, eventFinalize, caller, success, status, attrs)
}

func (r *Recorder) emit(ctx *azugo.Context, eventType, caller string, success bool, status int, attrs map[string]any) {
	if r == nil || r.sec == nil {
		return
	}
	out, sev := outcome(success)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[secevents.AttrSeverity] = string(sev)
	attrs["status"] = status

	ev := &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySecurity},
		Actor:      &broker.Actor{ID: caller, Type: "service"},
		Outcome:    out,
		Attributes: attrs,
	}
	if err := r.sec.Emit(ctx, ev); err != nil {
		r.log.Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
	}
}

// ---- GDPR-audit — personal-data access (go-gdpr-audit → access-audit) ---------

// IdentityValidated records that the engine validated and processed a person's
// eID identity (auth) — a personal-data access. subjectID is the raw national
// id; it is pseudonymized here and never stored raw. No-op when GDPR-audit is off.
func (r *Recorder) IdentityValidated(ctx *azugo.Context, caller, subjectID string) {
	r.access(ctx, eventIdentityValidated, caller, subjectID, gdpr.ResourceIdentity, broker.OpRead, gdpr.PurposeAccountManagement)
}

// SigningCertAccessed records the engine processing a person's signing
// certificate (/sign/certificate). No-op when GDPR-audit is off.
func (r *Recorder) SigningCertAccessed(ctx *azugo.Context, caller, subjectID string) {
	r.access(ctx, eventSigningCertAccess, caller, subjectID, "certificate", broker.OpRead, gdpr.PurposeSigning)
}

// FinalizeCertAccessed records the engine processing a person's certificate(s)
// at finalize. No-op when GDPR-audit is off.
func (r *Recorder) FinalizeCertAccessed(ctx *azugo.Context, caller, subjectID string) {
	r.access(ctx, eventFinalizeCertAccess, caller, subjectID, "certificate", broker.OpSign, gdpr.PurposeSigning)
}

func (r *Recorder) access(ctx *azugo.Context, eventType, caller, subjectID, resourceType string, op broker.Operation, purpose string) {
	if r == nil || r.gdpr == nil || r.psn == nil {
		return
	}

	ref := r.psn.Ref(subjectID)
	if ref == "" {
		return
	}

	err := r.gdpr.Record(ctx, eventType, gdpr.Access{
		Actor:        broker.Actor{ID: caller, Type: "service"},
		DataSubjects: []string{ref},
		Resource:     broker.Resource{Type: resourceType},
		Operation:    op,
		LawfulBasis:  gdpr.BasisContract,
		Purpose:      purpose,
		Channel:      gdpr.ChannelBackground, // server-to-server engine call
	})
	if err != nil {
		// Routine / fail-open: never break validation or signing on audit pressure.
		r.log.Warn("gdpr access record not persisted (non-fatal)",
			zap.String("event_type", eventType), zap.Error(err))
	}
}

func outcome(success bool) (broker.Outcome, secevents.Severity) {
	if success {
		return broker.OutcomeSuccess, secevents.SeverityInfo
	}

	return broker.OutcomeFailure, secevents.SeverityWarning
}
