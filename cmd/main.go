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
	acquiredSvid := make(chan bool, 1)
	updatedSecret := make(chan bool, 1)

	log.InfoLn(updatedSecret)

	go bootstrap.NotifyTimeout(timedOut)
	go bootstrap.CreateCryptoKey()
	go bootstrap.Monitor(acquiredSvid, updatedSecret, timedOut)

	go probe.CreateLiveness()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := bootstrap.AcquireSource(ctx, acquiredSvid)
	server.Serve(source)
}
