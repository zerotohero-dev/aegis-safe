/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package route

import (
	"encoding/json"
	"github.com/zerotohero-dev/aegis-safe/internal/log"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	reqres "github.com/zerotohero-dev/aegis/core/entity/reqres/v1"
	"github.com/zerotohero-dev/aegis/core/validation"
	"io"
	"net/http"
)

func Secret(w http.ResponseWriter, r *http.Request, svid string) {
	if r == nil {
		return
	}

	if !validation.IsSentinel(svid) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Problem sending response")
		}
		return
	}

	log.DebugLn("Secret: sentinel svid:", svid)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Secret: Problem sending response")
		}
		return
	}
	defer func(b io.ReadCloser) {
		if b == nil {
			return
		}
		err := b.Close()
		if err != nil {
			log.InfoLn("Secret: Problem closing body")
		}
	}(r.Body)

	log.DebugLn("Secret: Parsed request body")

	var sr reqres.SecretUpsertRequest
	err = json.Unmarshal(body, &sr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Secret: Problem sending response")
		}
		return
	}

	workloadId := sr.WorkloadId
	value := sr.Value

	log.DebugLn("Secret:Upsert: workloadId:", workloadId)
	state.UpsertSecret(workloadId, value)
	log.DebugLn("Secret:UpsertEnd: workloadId", workloadId)

	_, err = io.WriteString(w, "OK")
	if err != nil {
		log.InfoLn("Secret: Problem sending response")
	}
}
