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
	"github.com/zerotohero-dev/aegis-core/probe"
	"github.com/zerotohero-dev/aegis-safe/internal/bootstrap"
	"github.com/zerotohero-dev/aegis-safe/internal/log"
	"github.com/zerotohero-dev/aegis-safe/internal/server"
)

func main() {
	log.InfoLn("Acquiring identity…")

	timedOut := make(chan bool, 1)
	// TODO: wait for these two channels before firing the readiness probe.
	acquiredSvid := make(chan bool, 1)
	updatedSecret := make(chan bool, 1)
	serverStarted := make(chan bool, 1)

	log.InfoLn(updatedSecret)

	go bootstrap.NotifyTimeout(timedOut)
	go bootstrap.CreateCryptoKey(updatedSecret)
	go bootstrap.Monitor(acquiredSvid, updatedSecret, serverStarted, timedOut)

	go probe.CreateLiveness()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := bootstrap.AcquireSource(ctx, acquiredSvid)
	defer func() {
		if err := source.Close(); err != nil {
			log.InfoLn("Problem closing SVID Bundle source: %v\n", err)
		}
	}()

	server.Serve(source, serverStarted)
}
