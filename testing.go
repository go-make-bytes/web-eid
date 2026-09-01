package webeid

import (
	"path/filepath"
	"runtime"
	"testing"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
)

// TestApp builds an App for tests: it points the engine at the self-signed CA
// fixture in testdata/, disables OCSP egress, and installs a stub auth
// middleware driven by the X-Test-Scopes request header (production wiring
// always uses the go-authbyte DPoP middleware).
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("SERVICE_NAME", "web-eid")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_ISSUER_URL", "http://localhost:8080")
	tb.Setenv("SERVICE_AUDIENCE", "svc:web-eid")

	tb.Setenv("WEBEID_ORIGIN", "https://localhost:8080")
	tb.Setenv("WEBEID_TRUSTED_CA_CERTS_PATH", testdataDir())
	tb.Setenv("WEBEID_OCSP_ENABLED", "false")

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	app.SetAuthMiddleware(TestAuthMiddleware())
	return app
}

// testdataDir resolves the package-local testdata directory as an absolute path
// so the fixture is found regardless of the test's working directory (e.g. when
// TestApp is invoked from the routes sub-package).
func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata")
}

// TestAuthMiddleware authenticates requests carrying the X-Test-Scopes header
// (comma-separated scopes, e.g. "signatures:read"). Requests without it are
// rejected 401 — mirroring the production middleware contract.
func TestAuthMiddleware() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			scopes := ctx.Header.Get("X-Test-Scopes")
			if scopes == "" {
				ctx.StatusCode(401)
				ctx.Text("unauthorized")
				return
			}
			ctx.SetUser(user.New(map[string]token.ClaimStrings{
				"sub":   {"svc:test-client"},
				"scope": {scopes},
			}))
			next(ctx)
		}
	}
}
