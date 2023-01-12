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
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	reqres "github.com/zerotohero-dev/aegis/core/entity/reqres/v1"
	"github.com/zerotohero-dev/aegis/core/validation"
	"io"
	"log"
	"net/http"
	"strings"
)

func Fetch(w http.ResponseWriter, r *http.Request, svid string) {
	// Only workloads can fetch.
	if !validation.IsWorkload(svid) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.Println("Problem sending response")
		}
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.Println("Problem sending response")
		}
		return
	}

	defer func() {
		err := r.Body.Close()
		if err != nil {
			log.Println("Problem closing body")
		}
	}()

	var sr reqres.SecretFetchRequest
	err = json.Unmarshal(body, &sr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.Println("Problem sending response")
		}
		return
	}

	tmp := strings.Replace(svid, env.WorkloadSvidPrefix(), "", 1)
	parts := strings.Split(tmp, "/")
	if len(parts) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.Println("Problem sending response")
		}
		return
	}

	workloadId := parts[0]
	value := state.ReadSecret(workloadId)

	sfr := reqres.SecretFetchResponse{
		Data: value,
	}

	resp, err := json.Marshal(sfr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := io.WriteString(w, "Problem unmarshaling response")
		if err != nil {
			log.Println("Problem sending response")
		}
		return
	}

	_, err = io.WriteString(w, string(resp))
	if err != nil {
		log.Println("Problem sending response")
	}
}
