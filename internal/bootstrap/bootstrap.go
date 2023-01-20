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
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-safe/internal/log"
	"github.com/zerotohero-dev/aegis-safe/internal/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"time"
)

func NotifyTimeout(timedOut chan<- bool) {
	time.Sleep(env.SafeSvidRetrievalTimeout())
	timedOut <- true
}

func Monitor(
	acquiredSvid <-chan bool,
	updatedSecret <-chan bool,
	timedOut <-chan bool,
) {
	select {
	case <-acquiredSvid:
		log.InfoLn("Acquired identity.")
	case <-updatedSecret:
		log.InfoLn("Updated age key.")
	case <-timedOut:
		log.FatalLn("Failed to acquire an identity in a timely manner.")
	}
}

func AcquireSource(ctx context.Context, acquiredSvid chan<- bool) *workloadapi.X509Source {
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
	acquiredSvid <- true

	return source
}

func osman() {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.FatalLn("Error creating client config: %v", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.FatalLn("Error creating client: %v", err.Error())
	}

	log.InfoLn(clientset)

	// Update the Secret
	//secret := []byte("new-secret-data")
	//secretName := "my-secret"
	//_, err = clientset.CoreV1().Secrets("default").Update(&v1.Secret{
	//	ObjectMeta: metav1.ObjectMeta{
	//		Name: secretName,
	//	},
	//	Data: map[string][]byte{
	//		"data": secret,
	//	},
	//})
	//if err != nil {
	//	log.Fatalf("Error updating secret: %v", err)
	//}
}

func CreateCryptoKey() {
	// TODO:
	// 1. check the mounted volume to see if there is a key there
	// 2. if yes, store it in memory, if no proceed to the slower path
	// 3. create a new age key
	// 4. save the age key to memory.
	// 5. update the secret to save the key into it.
	// 6. notify that this step is done, and we can proceed to the next step
	// of bootstrapping.
	osman()
}
