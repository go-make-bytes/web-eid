// Package trustsync implements the web-eid engine's Mode A trust-bundle sync:
// it pulls trusted-CA material from
// the trust-anchor service over the authenticated HTTP API (DPoP service token,
// ETag/304) and writes a single managed PEM file into the directory go-web-eid
// already reads (WEBEID_TRUSTED_CA_CERTS_PATH), so operator-added PEMs in the
// same directory coexist untouched. The engine never reads the trust-anchor
// database — API + local cache only. On any error the existing
// files are left in place (fail-safe); the library keeps serving them.
package trustsync

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"azugo.io/azugo"
	"azugo.io/core"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// defaultManagedName is the filename the sync owns inside the trust directory.
// The leading "00-" keeps it first when the library loads the directory; every
// other file (operator-added PEMs) is left untouched.
const defaultManagedName = "00-trust-anchor.pem"

// Options configures a Syncer.
type Options struct {
	AnchorsURL  string // full trust-anchor /v1/anchors URL incl. filters
	Audience    string // target audience for the service token, e.g. svc:trust-anchor
	Scope       string // e.g. trust:read
	DestDir     string // WEBEID_TRUSTED_CA_CERTS_PATH directory
	ManagedName string // managed file written into DestDir (default 00-trust-anchor.pem)
	Log         *zap.Logger

	// OnChange is called after the managed bundle is (re)written, so the
	// hosting engine can reload its trusted set from the directory — a
	// written bundle must be the one the next validation uses, not the one
	// the next restart finds. An OnChange error fails the sync WITHOUT
	// recording the new ETag: the next tick refetches the bundle and retries
	// the reload instead of settling on 304s while the engine still enforces
	// the previous set.
	OnChange func() error
}

// doer issues a background DPoP service-to-service request. *authclient.Client
// satisfies it (authclient.DoService); tests inject a stub.
type doer interface {
	DoService(ctx context.Context, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
}

// Syncer fetches the trust-anchor PEM bundle and maintains the managed file.
// It is not safe for concurrent Sync calls; drive it from a single task.
// Status is safe to read from any goroutine.
type Syncer struct {
	auth doer
	opt  Options
	etag string // last seen ETag, sent as If-None-Match

	mu     sync.Mutex
	status Status
}

// Status is the sync half of the trust identity this engine can report: the
// upstream snapshot the managed bundle on disk came from, when it was last
// confirmed, and whether the engine's enforced set follows it. With an
// OnChange reloader wired, ReloadedAt equal to ChangedAt means the enforced
// set IS the on-disk set; a ReloadedAt behind ChangedAt means the engine is
// still serving the previous set (a reload failed and will be retried).
type Status struct {
	// UpstreamSnapshotID is the trust-service snapshot id of the managed
	// bundle written by this process (from the bundle ETag). Empty until the
	// first successful full fetch.
	UpstreamSnapshotID string
	// FetchedAt is the time of the last successful sync — a fresh bundle or
	// a confirmed not-modified both count.
	FetchedAt time.Time
	// ChangedAt is the time this process last rewrote the managed bundle.
	ChangedAt time.Time
	// ReloadedAt is the time the hosting engine last reloaded its trusted
	// set from a fresh bundle (via OnChange). Zero when no reloader is
	// wired or no bundle has been applied yet this process.
	ReloadedAt time.Time
	// ConsecutiveFailures counts sync attempts that have failed in a row —
	// fetch errors, rejected bundles, and bundles written but not applied
	// all count. Reset to zero by any successful sync. A growing count is
	// the signal that the engine is drifting on an ageing trusted set.
	ConsecutiveFailures int
}

// Status returns the current sync status.
func (s *Syncer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// New builds a Syncer. auth is normally *authclient.Client (it satisfies doer).
func New(auth doer, opt Options) *Syncer {
	if opt.ManagedName == "" {
		opt.ManagedName = defaultManagedName
	}

	return &Syncer{auth: auth, opt: opt}
}

// Sync fetches /v1/anchors with the last ETag. On 304 it is a no-op; on 200 it
// atomically rewrites the managed PEM file, hands it to OnChange (when wired)
// and records the new ETag. Errors are returned for the caller to log — the
// existing managed/manual files are never removed on failure.
func (s *Syncer) Sync(ctx context.Context) error {
	err := s.sync(ctx)
	s.mu.Lock()
	if err != nil {
		s.status.ConsecutiveFailures++
	} else {
		s.status.ConsecutiveFailures = 0
	}
	s.mu.Unlock()

	return err
}

func (s *Syncer) sync(ctx context.Context) error {
	hdr := http.Header{}
	if s.etag != "" {
		hdr.Set("If-None-Match", s.etag)
	}

	resp, err := s.auth.DoService(ctx, s.opt.Audience, s.opt.Scope, http.MethodGet, s.opt.AnchorsURL, hdr, nil)
	if err != nil {
		return fmt.Errorf("trustsync: fetch anchors: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusNotModified:
		// Upstream confirmed the bundle we hold is current — a successful
		// sync for freshness purposes, with nothing rewritten.
		s.mu.Lock()
		s.status.FetchedAt = time.Now().UTC()
		s.mu.Unlock()
		return nil
	case http.StatusOK:
		if len(resp.Body) == 0 {
			return fmt.Errorf("trustsync: empty anchors bundle")
		}
		if err := s.writeManaged(resp.Body); err != nil {
			return err
		}
		// Apply before recording: a bundle written but not applied must fail
		// the sync with the old ETag kept, so the next tick refetches and
		// retries the reload rather than confirming freshness on 304s while
		// the engine still enforces the previous set.
		reloaded := false
		if s.opt.OnChange != nil {
			if err := s.opt.OnChange(); err != nil {
				return fmt.Errorf("trustsync: bundle written but not applied: %w", err)
			}
			reloaded = true
		}
		if et := resp.Header.Get("ETag"); et != "" {
			s.etag = et
		}
		now := time.Now().UTC()
		s.mu.Lock()
		s.status.UpstreamSnapshotID = strings.Trim(s.etag, `"`)
		s.status.FetchedAt = now
		s.status.ChangedAt = now
		if reloaded {
			s.status.ReloadedAt = now
		}
		s.mu.Unlock()
		if s.opt.Log != nil {
			s.opt.Log.Info("trust bundle updated",
				zap.String("file", filepath.Join(s.opt.DestDir, s.opt.ManagedName)),
				zap.Int("bytes", len(resp.Body)))
			// The managed set changed on disk: re-inventory the directory so
			// the log always holds the current union.
			LogInventory(s.opt.Log, s.opt.DestDir, s.opt.ManagedName)
		}

		return nil
	default:
		return fmt.Errorf("trustsync: anchors returned status %d", resp.StatusCode)
	}
}

// writeManaged atomically writes the managed PEM file inside DestDir (temp +
// rename), leaving every other file in the directory untouched.
func (s *Syncer) writeManaged(pem []byte) error {
	if s.opt.DestDir == "" {
		return fmt.Errorf("trustsync: no destination directory configured")
	}
	if err := os.MkdirAll(s.opt.DestDir, 0o750); err != nil {
		return fmt.Errorf("trustsync: ensure dir: %w", err)
	}

	target := filepath.Join(s.opt.DestDir, s.opt.ManagedName)
	tmp := target + ".tmp"

	if err := os.WriteFile(tmp, pem, 0o600); err != nil {
		return fmt.Errorf("trustsync: write temp: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("trustsync: rename: %w", err)
	}

	return nil
}

// task adapts a Syncer to core.Tasker: an initial sync at startup, then on a
// ticker. Sync failures are logged, never fatal — go-web-eid keeps serving the
// existing trust directory (fail-safe).
type task struct {
	app      *azugo.App
	syncer   *Syncer
	interval time.Duration
	ticker   *time.Ticker
	stop     chan struct{}
}

// NewTask wraps a Syncer as a background task that syncs at startup and every
// interval (default 1h when interval <= 0).
func NewTask(app *azugo.App, syncer *Syncer, interval time.Duration) core.Tasker {
	if interval <= 0 {
		interval = time.Hour
	}

	return &task{app: app, syncer: syncer, interval: interval}
}

func (t *task) Name() string { return "trust-sync" }

func (t *task) Start(ctx context.Context) error {
	// Startup inventory BEFORE the initial sync: this names what the engine
	// actually loaded at boot. A fresh bundle fetched below rewrites the
	// disk, is applied to the running engine via OnChange, and logs its own
	// inventory — the difference between the two lines is what the first
	// sync delivered.
	LogInventory(t.app.Log(), t.syncer.opt.DestDir, t.syncer.opt.ManagedName)
	if err := t.syncer.Sync(ctx); err != nil {
		t.app.Log().Warn("initial trust sync failed; serving existing trust dir", zap.Error(err))
	}

	t.ticker = time.NewTicker(t.interval)
	t.stop = make(chan struct{})

	go func() {
		for {
			select {
			case <-t.stop:
				return
			case <-t.ticker.C:
				if err := t.syncer.Sync(ctx); err != nil {
					t.app.Log().Warn("trust sync failed", zap.Error(err))
				}
			}
		}
	}()

	return nil
}

func (t *task) Stop() {
	if t.ticker != nil {
		t.ticker.Stop()
		close(t.stop)
		t.ticker = nil
	}
}
