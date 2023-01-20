/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package bootstrap

import (
	"context"
	"filippo.io/age"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/probe"
	"github.com/zerotohero-dev/aegis-safe/internal/log"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	"github.com/zerotohero-dev/aegis-safe/internal/validation"
	"os"
	"time"
)

func NotifyTimeout(timedOut chan<- bool) {
	time.Sleep(env.SafeSvidRetrievalTimeout())
	timedOut <- true
}

func Monitor(
	acquiredSvid <-chan bool,
	updatedSecret <-chan bool,
	serverStarted <-chan bool,
	timedOut <-chan bool,
) {
	counter := 3
	select {
	case <-acquiredSvid:
		log.InfoLn("Acquired identity.")
		counter--
		if counter == 0 {
			log.DebugLn("Creating readiness probe.")
			go probe.CreateReadiness()
		}
	case <-updatedSecret:
		log.InfoLn("Updated age key.")
		counter--
		if counter == 0 {
			log.DebugLn("Creating readiness probe.")
			go probe.CreateReadiness()
		}
	case <-serverStarted:
		log.InfoLn("Server ready.")
		counter--
		if counter == 0 {
			log.DebugLn("Creating readiness probe.")
			go probe.CreateReadiness()
		}
	case <-timedOut:
		log.FatalLn("Failed to acquire an identity in a timely manner.")
	}
}

func AcquireSource(
	ctx context.Context, acquiredSvid chan<- bool,
) *workloadapi.X509Source {
	source, err := workloadapi.NewX509Source(
		ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr(env.SpiffeSocketUrl()),
		),
	)

	if err != nil {
		log.FatalLn("Unable to fetch X.509 Bundle: %v", err)
	}

	validation.EnsureSelfSPIFFEID(source)
	acquiredSvid <- true

	return source
}

func CreateCryptoKey(updatedSecret chan<- bool) {
	keyPath := env.SafeAgeKeyPath()

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.FatalLn("CreateCryptoKey: Secret key not mounted at", keyPath)
		return
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		log.FatalLn("CreateCryptoKey: Error reading file:", err.Error())
		return
	}

	secret := string(data)

	const uninitialized = "{}"

	if secret != uninitialized {
		log.InfoLn("Secret has been set in the cluster, will reuse it")
		state.SetAgeKey(secret)
		return
	}

	log.InfoLn("Secret has not been set yet. Will compute a secure secret.")

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.FatalLn("Failed to generate key pair: %v", err.Error())
	}

	publicKey := identity.Recipient().String()
	privateKey := identity.String()

	log.TraceLn("Public key: %s...\n", identity.Recipient().String()[:4])
	log.TraceLn("Private key: %s...\n", identity.String()[:16])

	persistKeys(privateKey, publicKey)
	updatedSecret <- true
}
