package webeid

import (
	"strings"
	"time"

	azugocfg "azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"
	webeidazugo "github.com/gmb-lib/go-web-eid/azugo"
)

// Configuration is the web-eid engine service configuration. It composes the
// platform base configuration with the inbound auth config and the go-web-eid
// engine config. The engine fields are bound under the "webeid" prefix and read
// the library's standard WEBEID_* environment variables.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// Auth is the go-authbyte inbound DPoP validation config
	// (AUTH_ISSUER_URL / SERVICE_AUDIENCE=svc:web-eid / …).
	Auth *authclient.Configuration `mapstructure:"auth"`

	// WebEID is the go-web-eid engine configuration: trusted CA material,
	// site origin, OCSP, nonce TTL, hash preference and accepted policy OIDs.
	WebEID *webeidazugo.Configuration `mapstructure:"webeid"`

	// Trust-bundle sync (P5b, Mode A). When TrustAnchorURL is set, the engine
	// pulls trust-anchor's /v1/anchors (ETag/304, DPoP service token) on startup
	// and on an interval, and writes a managed PEM file into the configured
	// WEBEID_TRUSTED_CA_CERTS_PATH directory so go-web-eid loads it alongside any
	// operator-added PEMs. Empty URL disables the sync (the library then relies
	// solely on whatever is already in that directory).
	TrustAnchorURL      string        `mapstructure:"trust_anchor_url" validate:"omitempty,url"`
	TrustAnchorAudience string        `mapstructure:"trust_anchor_audience"`
	TrustAnchorScope    string        `mapstructure:"trust_anchor_scope"`
	TrustSyncInterval   time.Duration `mapstructure:"trust_sync_interval" validate:"omitempty,gt=0"`
	// TrustSyncDir is the directory the managed bundle is written to. It binds to
	// the SAME env var the library reads (WEBEID_TRUSTED_CA_CERTS_PATH) so both
	// see one directory without coupling to the library's config struct.
	TrustSyncDir string `mapstructure:"trust_sync_dir"`

	// Audit — GDPR personal-data access logging (GDPR-audit) to access-audit.
	// OPTIONAL: when AccessAuditURL is empty the GDPR client is not wired (the
	// engine still emits NIS2-audit security telemetry). The engine processes eID
	// certificate PII, so when enabled it records each validated/processed
	// identity as a personal-data access — with a PSEUDONYMIZED subject ref.
	AccessAuditURL       string `mapstructure:"access_audit_url" validate:"omitempty,url"`
	AccessAuditAudience  string `mapstructure:"access_audit_audience"`
	AccessAuditScope     string `mapstructure:"access_audit_scope"`
	AccessAuditOutboxDir string `mapstructure:"access_audit_outbox_dir"`
	// AuditClientID / AuditClientSecret authenticate this engine's OUTBOUND
	// client-credentials hop (to the Auth service /token) to mint the service
	// token used to call access-audit. AuditClientID must be a registered client
	// with a grant for AccessAuditAudience/AccessAuditScope.
	AuditClientID     string `mapstructure:"audit_client_id"`
	AuditClientSecret string `mapstructure:"audit_client_secret"`
	// ServiceOutboundIssuerURL overrides the issuer base for ALL outbound S2S
	// token mints (trust-sync → trust-anchor, audit poster → access-audit). It
	// must be the IN-NETWORK Auth address; inbound validation keeps the public
	// Auth.IssuerURL. Independent of whether GDPR-audit (audit) is enabled.
	ServiceOutboundIssuerURL string `mapstructure:"service_outbound_issuer_url" validate:"omitempty,url"`
	// AuditIssuerURL is the legacy, audit-specific outbound issuer override.
	// Superseded by ServiceOutboundIssuerURL (AUTH_OUTBOUND_ISSUER_URL); kept as
	// a fallback so existing AUDIT_ISSUER_URL deployments don't break.
	AuditIssuerURL string `mapstructure:"audit_issuer_url" validate:"omitempty,url"`
	// PseudonymKey is the HMAC key used to pseudonymize the eID national id into
	// the GDPR-audit data-subject reference (so the raw id is never logged).
	// Required when AccessAuditURL is set.
	PseudonymKey string `mapstructure:"audit_subject_pseudonym_key"`
}

// NewConfiguration returns the configuration skeleton for binding.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// ServerCore returns the embedded azugo configuration.
func (c *Configuration) ServerCore() *azugocfg.Configuration {
	return c.Configuration
}

// Bind registers defaults and environment bindings.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)
	c.Auth = azugocfg.Bind(c.Auth, "auth", v)
	c.WebEID = azugocfg.Bind(c.WebEID, "webeid", v)

	// Trust-bundle sync (P5b).
	v.SetDefault("trust_anchor_audience", "svc:trust-anchor")
	v.SetDefault("trust_anchor_scope", "trust:read")
	v.SetDefault("trust_sync_interval", time.Hour)
	_ = v.BindEnv("trust_anchor_url", "WEBEID_TRUST_ANCHOR_URL")
	_ = v.BindEnv("trust_anchor_audience", "WEBEID_TRUST_ANCHOR_AUDIENCE")
	_ = v.BindEnv("trust_anchor_scope", "WEBEID_TRUST_ANCHOR_SCOPE")
	_ = v.BindEnv("trust_sync_interval", "WEBEID_TRUST_SYNC_INTERVAL")
	// Same env var the library reads, so the sync writes into the dir it loads.
	_ = v.BindEnv("trust_sync_dir", "WEBEID_TRUSTED_CA_CERTS_PATH")

	// Audit (GDPR-audit) — off until ACCESS_AUDIT_URL is set.
	v.SetDefault("access_audit_audience", "svc:access-audit")
	v.SetDefault("access_audit_scope", "access-audit:write")
	v.SetDefault("audit_client_id", "svc:web-eid")
	if secret, err := corecfg.LoadRemoteSecret("AUDIT_CLIENT_SECRET"); err == nil && secret != "" {
		v.SetDefault("audit_client_secret", secret)
	}
	if key, err := corecfg.LoadRemoteSecret("AUDIT_SUBJECT_PSEUDONYM_KEY"); err == nil && key != "" {
		v.SetDefault("audit_subject_pseudonym_key", key)
	}
	_ = v.BindEnv("access_audit_url", "ACCESS_AUDIT_URL")
	_ = v.BindEnv("access_audit_audience", "ACCESS_AUDIT_AUDIENCE")
	_ = v.BindEnv("access_audit_scope", "ACCESS_AUDIT_SCOPE")
	_ = v.BindEnv("access_audit_outbox_dir", "ACCESS_AUDIT_OUTBOX_DIR")
	_ = v.BindEnv("audit_client_id", "AUDIT_CLIENT_ID")
	_ = v.BindEnv("audit_client_secret", "AUDIT_CLIENT_SECRET")
	_ = v.BindEnv("service_outbound_issuer_url", "AUTH_OUTBOUND_ISSUER_URL")
	_ = v.BindEnv("audit_issuer_url", "AUDIT_ISSUER_URL") // legacy fallback
	_ = v.BindEnv("audit_subject_pseudonym_key", "AUDIT_SUBJECT_PSEUDONYM_KEY")

	// This engine is reached server-to-server (the SPA never addresses it), so
	// the request Host is the engine's internal address, never the signed SPA
	// origin — the library's default Host==Origin check can't hold here. Disable
	// it by default; the token's cryptographic origin binding still applies at
	// /auth/login. Operators fronting the engine at the public origin can
	// re-enable it with WEBEID_ENFORCE_HOST_HEADER=true.
	v.SetDefault("webeid.enforce_host_header", false)
}

// Validate validates the full configuration tree.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := c.Auth.Validate(valid); err != nil {
		return err
	}
	return c.WebEID.Validate(valid)
}

// AccessAuditEnabled reports whether GDPR (GDPR-audit) access logging is wired.
func (c *Configuration) AccessAuditEnabled() bool {
	return strings.TrimSpace(c.AccessAuditURL) != ""
}

// serviceIssuer returns the issuer base for outbound service-to-service token
// mints (trust-sync, audit poster). Precedence: the generic
// AUTH_OUTBOUND_ISSUER_URL, then the legacy audit-specific AUDIT_ISSUER_URL,
// then the inbound (public) Auth issuer.
func (c *Configuration) serviceIssuer() string {
	if u := strings.TrimSpace(c.ServiceOutboundIssuerURL); u != "" {
		return u
	}
	if u := strings.TrimSpace(c.AuditIssuerURL); u != "" { // legacy AUDIT_ISSUER_URL
		return u
	}

	return c.Auth.IssuerURL
}

// ServiceAuthClientConfig builds the OUTBOUND auth-client config for any S2S
// token mint (trust-sync → trust-anchor, audit poster → access-audit). It
// reuses the inbound Auth settings (JWKS/DPoP/nonce), points the issuer at the
// in-network outbound address, and adds this engine's service-client
// credentials, so it can mint DPoP-bound service tokens via client-credentials
// — independent of whether GDPR-audit (audit) is enabled.
func (c *Configuration) ServiceAuthClientConfig() *authclient.Configuration {
	cfg := *c.Auth // copy the validated inbound config
	cfg.IssuerURL = c.serviceIssuer()
	cfg.ServiceClientID = c.AuditClientID
	cfg.ServiceClientSecret = c.AuditClientSecret

	return &cfg
}

// GDPRConfig builds the go-gdpr-audit client configuration with default
// resilience knobs.
func (c *Configuration) GDPRConfig() gdpr.Configuration {
	return gdpr.Configuration{
		Endpoint:         c.AccessAuditURL,
		Audience:         c.AccessAuditAudience,
		Scope:            c.AccessAuditScope,
		Timeout:          gdpr.DefaultTimeout,
		OutboxCapacity:   gdpr.DefaultOutboxCapacity,
		MaxRetries:       gdpr.DefaultMaxRetries,
		RetryBackoff:     gdpr.DefaultRetryBackoff,
		BreakerThreshold: gdpr.DefaultBreakerThreshold,
		BreakerCooldown:  gdpr.DefaultBreakerCooldown,
	}
}

// PseudonymKeyBytes returns the raw HMAC pseudonym key bytes.
func (c *Configuration) PseudonymKeyBytes() []byte { return []byte(c.PseudonymKey) }
