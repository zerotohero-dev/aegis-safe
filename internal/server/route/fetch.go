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
	"fmt"
	reqres "github.com/zerotohero-dev/aegis-core/entity/reqres/v1"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/log"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	"github.com/zerotohero-dev/aegis/core/validation"
	"io"
	"net/http"
	"strings"
	"time"
)

func Fetch(w http.ResponseWriter, r *http.Request, svid string) {
	// Only workloads can fetch.
	if !validation.IsWorkload(svid) {
		log.DebugLn("Fetch: bad svid", svid)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response")
		}

		return
	}

	log.DebugLn("Fetch: sending response")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response")
		}

		return
	}

	log.DebugLn("Fetch: sent response")

	defer func() {
		err := r.Body.Close()
		if err != nil {
			log.InfoLn("Fetch: Problem closing body")
		}
	}()

	log.DebugLn("Fetch: preparing request")

	var sr reqres.SecretFetchRequest
	err = json.Unmarshal(body, &sr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response")
		}
		return
	}

	log.DebugLn("Fetch: prepared request")

	tmp := strings.Replace(svid, env.WorkloadSvidPrefix(), "", 1)
	parts := strings.Split(tmp, "/")
	if len(parts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem with svid", svid)
		}
		return
	}

	workloadId := parts[0]
	secret := state.ReadSecret(workloadId)

	// If secret does not exist, send an empty response.
	if secret == nil {
		w.WriteHeader(http.StatusNotFound)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response")
		}
		return
	}

	log.DebugLn("Fetch: will send. workload id:", workloadId)

	// RFC3339 is what Go uses internally when marshaling dates.
	// Choosing it to be consistent.
	sfr := reqres.SecretFetchResponse{
		Data:    secret.Value,
		Created: fmt.Sprintf("\"%s\"", secret.Created.Format(time.RFC3339)),
		Updated: fmt.Sprintf("\"%s\"", secret.Updated.Format(time.RFC3339)),
	}

	resp, err := json.Marshal(sfr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := io.WriteString(w, "Problem unmarshaling response")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response")
		}
		return
	}

	log.DebugLn("Fetch: before response")

	_, err = io.WriteString(w, string(resp))
	if err != nil {
		log.InfoLn("Problem sending response")
	}

	log.DebugLn("Fetch: after response")
}
