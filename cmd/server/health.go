package main

import (
	"azugo.io/azugo/server"
	"azugo.io/core/cli"

	app "github.com/go-make-bytes/web-eid"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Web eID Engine",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
