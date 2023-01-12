/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package handle

import (
	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/zerotohero-dev/aegis-safe/internal/server/route"
	"io"
	"log"
	"net/http"
)

func getSpiffeId(r *http.Request) (*spiffeid.ID, error) {
	tlsConnectionState := r.TLS
	if len(tlsConnectionState.PeerCertificates) == 0 {
		return nil, errors.New("no peer certs")
	}

	id, err := x509svid.IDFromCert(tlsConnectionState.PeerCertificates[0])
	if err != nil {
		return nil, errors.Wrap(err, "problem extracting svid")
	}

	return &id, nil
}

func InitializeRoutes() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		id, err := getSpiffeId(r)
		if err != nil {
			// Block insecure connection attempt.
			_, err = io.WriteString(w, "")
			if err != nil {
				log.Println("Problem writing response")
				return
			}
		}

		sid := id.String()
		p := r.URL.Path

		// Route to fetch secrets.
		// Only an Aegis-nominated workload is allowed to
		// call this API endpoint. Calling it from anywhere else will
		// error out.
		if r.Method == http.MethodPost && p == "/v1/fetch" {
			route.Fetch(w, r, sid)
			return
		}

		// Route to add secrets to Aegis Safe.
		// Only Aegis Sentinel is allowed to call this API endpoint.
		// Calling it from anywhere else will error out.
		if r.Method == http.MethodPost && p == "/v1/secret" {
			route.Secret(w, r, sid)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		_, err = io.WriteString(w, "")
		if err != nil {
			log.Println("Problem writing response")
			return
		}
	})
}
