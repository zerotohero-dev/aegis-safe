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
	"fmt"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/probe"
	"github.com/zerotohero-dev/aegis-safe/internal/server"
	"github.com/zerotohero-dev/aegis-safe/internal/validation"
	"log"
	"net/http"
)

func ok(w http.ResponseWriter, req *http.Request) {
	_, err := fmt.Fprintf(w, "OK")
	if err != nil {
		log.Printf("probe response failure: %s", err.Error())
		return
	}
}
func main() {
	log.Println("Acquiring identity…")

	go probe.CreateLiveness()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source, err := workloadapi.NewX509Source(
		ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr(env.SpiffeSocketUrl()),
		),
	)

	if err != nil {
		log.Fatalf("Unable to fetch X.509 Bundle: %v", err)
	}

	defer func() {
		if err := source.Close(); err != nil {
			log.Printf("Problem closing SVID Bundle source: %v\n", err)
		}
	}()

	validation.EnsureSelfSPIFFEID(source)
	log.Println("Acquired identity.")

	server.Serve(source)
}
