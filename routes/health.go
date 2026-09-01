package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// healthz is the liveness probe.
func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	ctx.Text("ok")
}

// readyz reports readiness: the Web eID engine (trusted CA material, validator
// and signer) was built successfully at startup.
func (r *router) readyz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	if r.WebEID() == nil {
		ctx.StatusCode(fasthttp.StatusServiceUnavailable)
		ctx.Text("engine not ready")
		return
	}
	ctx.Text("ready")
}
