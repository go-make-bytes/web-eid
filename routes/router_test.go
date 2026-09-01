package routes

import (
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	webeid "github.com/go-make-bytes/web-eid"
)

func testApp(t testing.TB) *azugo.TestApp {
	app := webeid.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

func TestHealthzIsPublic(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestReadyzIsPublic(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/readyz")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestChallengeRequiresAuth(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	// No X-Test-Scopes header → rejected by the inbound auth middleware.
	resp, err := app.TestClient().Get("/auth/challenge")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

func TestChallengeWithAuthIssuesNonce(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Get("/auth/challenge", tc.WithHeader("X-Test-Scopes", "signatures:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestTrustStatusRequiresAuth(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/v1/trust-status")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

func TestTrustStatusReportsUnconfiguredSync(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Get("/v1/trust-status", tc.WithHeader("X-Test-Scopes", "signatures:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Check(t, qt.StringContains(string(resp.Body()), `"syncConfigured":false`))
	fasthttp.ReleaseResponse(resp)
}
