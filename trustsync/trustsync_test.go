package trustsync

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// stubDoer is a doer that returns canned responses and records the requests it
// saw (so tests can assert on the If-None-Match header).
type stubDoer struct {
	resp  *authclient.BackgroundResponse
	err   error
	calls []string // If-None-Match per call
}

func (s *stubDoer) DoService(_ context.Context, _, _, _, _ string, reqHeader http.Header, _ []byte) (*authclient.BackgroundResponse, error) {
	inm := ""
	if reqHeader != nil {
		inm = reqHeader.Get("If-None-Match")
	}
	s.calls = append(s.calls, inm)

	return s.resp, s.err
}

func resp(status int, etag, body string) *authclient.BackgroundResponse {
	h := http.Header{}
	if etag != "" {
		h.Set("ETag", etag)
	}

	return &authclient.BackgroundResponse{StatusCode: status, Header: h, Body: []byte(body)}
}

func newSyncer(d doer, dir string) *Syncer {
	return New(d, Options{
		AnchorsURL: "https://trust-anchor:8080/v1/anchors?territory=LV&use=signature",
		Audience:   "svc:trust-anchor",
		Scope:      "trust:read",
		DestDir:    dir,
	})
}

func managed(dir string) string { return filepath.Join(dir, defaultManagedName) }

func TestSyncWrites200AndLeavesManualPEMs(t *testing.T) {
	dir := t.TempDir()
	manual := filepath.Join(dir, "operator-root.pem")
	if err := os.WriteFile(manual, []byte("MANUAL-PEM"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newSyncer(&stubDoer{resp: resp(http.StatusOK, `"v1"`, "BUNDLE-1")}, dir)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	got, err := os.ReadFile(managed(dir))
	if err != nil || string(got) != "BUNDLE-1" {
		t.Fatalf("managed file = %q (err %v), want BUNDLE-1", got, err)
	}
	if m, _ := os.ReadFile(manual); string(m) != "MANUAL-PEM" {
		t.Errorf("operator PEM was clobbered: %q", m)
	}
}

func TestSync304IsNoOpAndSendsETag(t *testing.T) {
	dir := t.TempDir()
	stub := &stubDoer{resp: resp(http.StatusOK, `"v1"`, "BUNDLE-1")}
	s := newSyncer(stub, dir)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Upstream now reports not-modified: the managed file must be left as-is, and
	// the request must carry the ETag captured from the first 200.
	stub.resp = resp(http.StatusNotModified, "", "")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("304 sync returned error: %v", err)
	}

	if got, _ := os.ReadFile(managed(dir)); string(got) != "BUNDLE-1" {
		t.Errorf("managed file changed on 304: %q", got)
	}
	if len(stub.calls) != 2 {
		t.Fatalf("got %d calls, want 2", len(stub.calls))
	}
	if stub.calls[0] != "" {
		t.Errorf("first call sent If-None-Match %q, want empty", stub.calls[0])
	}
	if stub.calls[1] != `"v1"` {
		t.Errorf("second call If-None-Match = %q, want \"v1\"", stub.calls[1])
	}
}

func TestSyncErrorIsFailSafe(t *testing.T) {
	dir := t.TempDir()
	// An existing managed bundle (e.g. from a prior successful sync).
	if err := os.WriteFile(managed(dir), []byte("OLD-BUNDLE"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newSyncer(&stubDoer{err: errors.New("trust-anchor unreachable")}, dir)
	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error from failed fetch")
	}
	if got, _ := os.ReadFile(managed(dir)); string(got) != "OLD-BUNDLE" {
		t.Errorf("managed file changed on error: %q", got)
	}
}

func TestSyncRejectsBadStatus(t *testing.T) {
	dir := t.TempDir()
	s := newSyncer(&stubDoer{resp: resp(http.StatusInternalServerError, "", "boom")}, dir)
	if err := s.Sync(context.Background()); err == nil {
		t.Error("expected error on 500")
	}
	if _, err := os.Stat(managed(dir)); !os.IsNotExist(err) {
		t.Error("managed file written despite 500")
	}
}

func TestSyncRejectsEmptyBody(t *testing.T) {
	dir := t.TempDir()
	s := newSyncer(&stubDoer{resp: resp(http.StatusOK, `"v1"`, "")}, dir)
	if err := s.Sync(context.Background()); err == nil {
		t.Error("expected error on empty 200 body")
	}
	if _, err := os.Stat(managed(dir)); !os.IsNotExist(err) {
		t.Error("managed file written despite empty body")
	}
}

func TestStatusTracksSyncOutcomes(t *testing.T) {
	dir := t.TempDir()
	stub := &stubDoer{resp: resp(http.StatusOK, `"snap-1"`, "BUNDLE-1")}
	s := newSyncer(stub, dir)

	if st := s.Status(); st.UpstreamSnapshotID != "" || !st.FetchedAt.IsZero() {
		t.Fatalf("pre-sync status not empty: %+v", st)
	}

	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.UpstreamSnapshotID != "snap-1" {
		t.Fatalf("UpstreamSnapshotID = %q, want snap-1 (ETag unquoted)", st.UpstreamSnapshotID)
	}
	if st.FetchedAt.IsZero() || !st.ChangedAt.Equal(st.FetchedAt) {
		t.Fatalf("first 200 must stamp fetched == changed: %+v", st)
	}

	// A 304 confirms freshness without a rewrite: fetched advances (or at
	// least stays set), changed and the id stay.
	stub.resp = resp(http.StatusNotModified, "", "")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	st2 := s.Status()
	if st2.UpstreamSnapshotID != "snap-1" || !st2.ChangedAt.Equal(st.ChangedAt) {
		t.Fatalf("304 must keep id and changedAt: %+v", st2)
	}
	if st2.FetchedAt.Before(st.FetchedAt) {
		t.Fatalf("304 must refresh FetchedAt: %+v then %+v", st, st2)
	}
}

func TestSyncCallsOnChangeOnFreshBundleNotOn304(t *testing.T) {
	dir := t.TempDir()
	stub := &stubDoer{resp: resp(http.StatusOK, `"v1"`, "BUNDLE-1")}
	calls := 0
	s := New(stub, Options{AnchorsURL: "https://trust-anchor/v1/anchors", DestDir: dir,
		OnChange: func() error { calls++; return nil }})

	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("OnChange calls after fresh bundle = %d, want 1", calls)
	}
	if st := s.Status(); st.ReloadedAt.IsZero() || !st.ReloadedAt.Equal(st.ChangedAt) {
		t.Fatalf("applied bundle must stamp ReloadedAt == ChangedAt: %+v", st)
	}

	// A 304 confirms the bundle we already applied — no reload.
	stub.resp = resp(http.StatusNotModified, "", "")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("OnChange called on 304: %d calls", calls)
	}
}

func TestSyncOnChangeFailureKeepsETagSoNextTickRetries(t *testing.T) {
	dir := t.TempDir()
	stub := &stubDoer{resp: resp(http.StatusOK, `"v1"`, "BUNDLE-1")}
	fail := true
	s := New(stub, Options{AnchorsURL: "https://trust-anchor/v1/anchors", DestDir: dir,
		OnChange: func() error {
			if fail {
				return errors.New("engine reload failed")
			}
			return nil
		}})

	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error when the written bundle cannot be applied")
	}
	st := s.Status()
	if st.ConsecutiveFailures != 1 {
		t.Fatalf("ConsecutiveFailures = %d, want 1", st.ConsecutiveFailures)
	}
	if !st.ReloadedAt.IsZero() || !st.ChangedAt.IsZero() {
		t.Fatalf("an unapplied bundle must not stamp applied state: %+v", st)
	}

	// The ETag must NOT have been recorded: the retry refetches the full
	// bundle (empty If-None-Match) instead of settling on 304s while the
	// engine still enforces the previous set.
	fail = false
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := stub.calls[1]; got != "" {
		t.Fatalf("retry sent If-None-Match %q, want empty (full refetch)", got)
	}
	st = s.Status()
	if st.ConsecutiveFailures != 0 || st.ReloadedAt.IsZero() {
		t.Fatalf("recovered sync must reset failures and stamp ReloadedAt: %+v", st)
	}
}

func TestStatusCountsConsecutiveFailuresAndResets(t *testing.T) {
	dir := t.TempDir()
	stub := &stubDoer{err: errors.New("trust-anchor unreachable")}
	s := newSyncer(stub, dir)

	for want := 1; want <= 2; want++ {
		if err := s.Sync(context.Background()); err == nil {
			t.Fatal("expected fetch error")
		}
		if got := s.Status().ConsecutiveFailures; got != want {
			t.Fatalf("ConsecutiveFailures = %d, want %d", got, want)
		}
	}

	stub.err = nil
	stub.resp = resp(http.StatusOK, `"v1"`, "BUNDLE-1")
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.Status().ConsecutiveFailures; got != 0 {
		t.Fatalf("ConsecutiveFailures after success = %d, want 0", got)
	}
	// No OnChange wired: the sync succeeds without stamping ReloadedAt.
	if !s.Status().ReloadedAt.IsZero() {
		t.Fatal("ReloadedAt stamped without a reloader wired")
	}
}

func TestInventoryNamesLocalCertsAndCountsManaged(t *testing.T) {
	dir := t.TempDir()
	ca, err := os.ReadFile(filepath.Join("..", "testdata", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	// Managed bundle: two certificates (the same CA twice is fine for a
	// count). Local: one operator-placed PEM and one broken file.
	if err := os.WriteFile(managed(dir), append(append([]byte{}, ca...), ca...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "10-local-ca.pem"), ca, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "99-broken.crt"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	core, logs := observer.New(zap.InfoLevel)
	LogInventory(zap.New(core), dir, "")

	var entry *observer.LoggedEntry
	for _, e := range logs.All() {
		if e.Message == "trust inventory" {
			e := e
			entry = &e
		}
	}
	if entry == nil {
		t.Fatal("no trust inventory entry logged")
	}
	m := entry.ContextMap()
	if m["managed_present"] != true || m["managed_count"] != int64(2) {
		t.Fatalf("managed not counted: present=%v count=%v", m["managed_present"], m["managed_count"])
	}
	if m["local_count"] != int64(1) {
		t.Fatalf("local_count = %v, want 1", m["local_count"])
	}
	locals := fmt.Sprintf("%v", m["local_certs"])
	if !strings.Contains(locals, "10-local-ca.pem") || !strings.Contains(locals, "local") {
		t.Fatalf("local cert not named with file+origin: %s", locals)
	}
	errsField := fmt.Sprintf("%v", m["errors"])
	if !strings.Contains(errsField, "99-broken.crt") {
		t.Fatalf("broken file not named: %s", errsField)
	}
}
