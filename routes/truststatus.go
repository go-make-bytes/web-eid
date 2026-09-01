package routes

import (
	"time"

	"azugo.io/azugo"
)

// trustStatus is the diagnostic trust-identity route: which upstream trust
// snapshot the managed bundle on disk came from and when it was last
// confirmed. Deliberately not part of readiness — a stale bundle is old
// data served safely, not an unhealthy process; a degraded health status
// would invite an orchestrator to restart a service that is serving fine.
// Staleness alerting belongs to monitoring; identity belongs here, because
// an id must never be a metric label.
func (r *router) trustStatus(ctx *azugo.Context) {
	s, every := r.TrustSync()
	if s == nil {
		ctx.JSON(map[string]any{"syncConfigured": false})
		return
	}
	st := s.Status()
	body := map[string]any{
		"syncConfigured":     true,
		"upstreamSnapshotId": st.UpstreamSnapshotID,
		// Stale: no successful sync (fresh or confirmed-unchanged) within
		// two intervals. Also true before the first successful sync of this
		// process — with nothing confirmed yet, claiming freshness would be
		// a guess.
		"stale": st.FetchedAt.IsZero() || time.Since(st.FetchedAt) > 2*every,
		// Sync attempts failed in a row (0 = last sync succeeded). A growing
		// count means the engine is drifting on an ageing trusted set —
		// worth alerting on well before `stale` flips.
		"consecutiveFailures": st.ConsecutiveFailures,
	}
	if !st.FetchedAt.IsZero() {
		body["fetchedAt"] = st.FetchedAt.UTC()
	}
	if !st.ChangedAt.IsZero() {
		body["changedAt"] = st.ChangedAt.UTC()
	}
	if !st.ReloadedAt.IsZero() {
		// When the engine last applied a fresh bundle to its running trusted
		// set. reloadedAt == changedAt: the enforced set IS the on-disk set;
		// reloadedAt behind changedAt: a reload failed and will be retried.
		body["reloadedAt"] = st.ReloadedAt.UTC()
	}
	ctx.JSON(body)
}
