package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
)

type captureSink struct {
	mu  sync.Mutex
	all []*broker.Envelope
}

func (s *captureSink) Emit(_ *azugo.Context, ev *broker.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = append(s.all, ev)

	return nil
}

func (s *captureSink) last() *broker.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.all) == 0 {
		return nil
	}

	return s.all[len(s.all)-1]
}

func (s *captureSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.all)
}

func withCtx(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
}

func str(v any) string { s, _ := v.(string); return s }

// testIDCode returns an eID national id in the PNO form the audit path expects:
// a country code, a date of birth as DDMMYY, and a serial. It is assembled from
// those parts at run time rather than written as a literal — an
// identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's
// code to a reader.
func testIDCode() string {
	const (
		country = "LV"
		serial  = 12345
	)

	dob := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

	return fmt.Sprintf("PNO%s-%s-%05d", country, dob.Format("020106"), serial)
}

func TestPseudonymizer(t *testing.T) {
	_, err := NewPseudonymizer(nil)
	qt.Check(t, qt.IsNotNil(err))

	p, err := NewPseudonymizer([]byte("a-32-byte-or-longer-pseudonym-key!"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(p.Ref(""), ""))

	id := testIDCode()

	r1 := p.Ref(id)
	r2 := p.Ref(id)
	qt.Check(t, qt.Equals(r1, r2))         // deterministic
	qt.Check(t, qt.IsTrue(len(r1) > 4))    // non-trivial
	qt.Check(t, qt.Equals(r1[:4], "psn:")) // tagged
	qt.Check(t, qt.Not(qt.Equals(r1, id))) // never the raw id

	other, err := NewPseudonymizer([]byte("a-different-key-aaaaaaaaaaaaaaaaaa"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(other.Ref(id), r1))) // key-sensitive
}

func TestAuthValidatedNis2Audit(t *testing.T) {
	sink := &captureSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.AuthValidated(ctx, "svc:authbyte-core", true, 200)
	})

	ev := sink.last()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventAuthentication))
	qt.Check(t, qt.Equals(ev.Outcome, broker.OutcomeSuccess))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityInfo)))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrMethod]), "web-eid"))
	qt.Assert(t, qt.IsNotNil(ev.Actor))
	qt.Check(t, qt.Equals(ev.Actor.ID, "svc:authbyte-core"))
	qt.Check(t, qt.Equals(ev.Actor.Type, "service"))
}

func TestAuthValidatedFailureIsWarning(t *testing.T) {
	sink := &captureSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.AuthValidated(ctx, "svc:authbyte-core", false, 401)
	})

	ev := sink.last()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.Outcome, broker.OutcomeFailure))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityWarning)))
}

func TestFinalizeCarriesIdentityBound(t *testing.T) {
	sink := &captureSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.Finalize(ctx, "svc:eparaksts-signer", true, 200, true)
	})

	ev := sink.last()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, eventFinalize))
	bound, _ := ev.Attributes["identity_bound"].(bool)
	qt.Check(t, qt.IsTrue(bound))
}

// GDPR-audit helpers must be safe no-ops when the gdpr client is not configured.
func TestGdprAuditNoopWithoutGDPR(t *testing.T) {
	sink := &captureSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, zap.NewNop())

	withCtx(t, func(ctx *azugo.Context) {
		rec.IdentityValidated(ctx, "svc:authbyte-core", testIDCode()) // must not panic
		rec.SigningCertAccessed(ctx, "svc:eparaksts-signer", testIDCode())
	})

	qt.Check(t, qt.Equals(sink.count(), 0)) // GDPR-audit path emits no security event
}

func TestMiddlewareDispatch(t *testing.T) {
	sink := &captureSink{}
	rec := New(secevents.NewEmitter(sink), nil, nil, zap.NewNop())

	app := azugo.NewTestApp()
	app.Use(rec.Middleware())
	app.Post("/auth/login", func(ctx *azugo.Context) {
		ctx.SetUser(user.New(map[string]token.ClaimStrings{"sub": {testIDCode()}}))
		ctx.JSON(map[string]string{"idCode": testIDCode()})
	})
	app.Post("/sign/certificate", func(ctx *azugo.Context) {
		ctx.StatusCode(fasthttp.StatusUnprocessableEntity)
		ctx.Text("bad cert")
	})
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	resp, err := tc.Post("/auth/login", []byte(`{}`))
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
	login := sink.last()
	qt.Assert(t, qt.IsNotNil(login))
	qt.Check(t, qt.Equals(login.EventType, secevents.EventAuthentication))
	qt.Check(t, qt.Equals(login.Outcome, broker.OutcomeSuccess))

	resp2, err := tc.Post("/sign/certificate", []byte(`{}`))
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp2)
	sign := sink.last()
	qt.Assert(t, qt.IsNotNil(sign))
	qt.Check(t, qt.Equals(sign.EventType, eventSigningCertificate))
	qt.Check(t, qt.Equals(sign.Outcome, broker.OutcomeFailure))
}
