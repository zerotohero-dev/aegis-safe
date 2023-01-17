/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package main

import (
	"context"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/probe"
	"github.com/zerotohero-dev/aegis-safe/internal/log"
	"github.com/zerotohero-dev/aegis-safe/internal/server"
	"github.com/zerotohero-dev/aegis-safe/internal/validation"
	"time"
)

func main() {
	log.InfoLn("Acquiring identity…")

	timedOut := make(chan bool, 1)
	acquired := make(chan bool, 1)
	go func() {
		time.Sleep(env.SafeSvidRetrievalTimeout())
		timedOut <- true
	}()
	go func() {
		select {
		case <-acquired:
			log.InfoLn("Acquired identity.")
		case <-timedOut:
			log.FatalLn("Failed to acquire an identity in a timely manner.")
		}
	}()

	go probe.CreateLiveness()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source, err := workloadapi.NewX509Source(
		ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr(env.SpiffeSocketUrl()),
		),
	)

	if err != nil {
		log.FatalLn("Unable to fetch X.509 Bundle: %v", err)
	}

	defer func() {
		if err := source.Close(); err != nil {
			log.InfoLn("Problem closing SVID Bundle source: %v\n", err)
		}
	}()

	validation.EnsureSelfSPIFFEID(source)
	acquired <- true

	server.Serve(source)
}
