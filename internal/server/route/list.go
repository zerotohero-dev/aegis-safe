/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                    <aegis.ist>
 *     .\_/.
 */

package route

import (
	"encoding/json"
	"github.com/zerotohero-dev/aegis-core/audit"
	"github.com/zerotohero-dev/aegis-core/crypto"
	reqres "github.com/zerotohero-dev/aegis-core/entity/reqres/safe/v1"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/log"
	"github.com/zerotohero-dev/aegis-core/validation"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	"io"
	"net/http"
	"strings"
)

func List(w http.ResponseWriter, r *http.Request, svid string) {
	correlationId, _ := crypto.RandomString(8)
	if correlationId == "" {
		correlationId = "CID"
	}

	j := audit.JournalEntry{
		CorrelationId: correlationId,
		Entity:        nil,
		Method:        r.Method,
		Url:           r.RequestURI,
		Svid:          svid,
		Event:         audit.EventEnter,
	}

	audit.Log(j)

	// Only sentinel can list.
	if !validation.IsSentinel(svid) {
		j.Event = audit.EventBadSvid
		audit.Log(j)

		log.DebugLn("List: bad svid", svid)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("List: Problem sending response", err.Error())
		}

		return
	}

	log.TraceLn("List: before defer")

	defer func() {
		err := r.Body.Close()
		if err != nil {
			log.InfoLn("List: Problem closing body")
		}
	}()

	log.TraceLn("List: after defer")

	tmp := strings.Replace(svid, env.SentinelSvidPrefix(), "", 1)
	parts := strings.Split(tmp, "/")
	if len(parts) == 0 {
		j.Event = audit.EventBadPeerSvid
		audit.Log(j)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("List: Problem with svid", svid)
		}
		return
	}

	workloadId := parts[0]
	secrets := state.AllSecrets()

	log.DebugLn("List: will send. workload id:", workloadId)

	// RFC3339 is what Go uses internally when marshaling dates.
	// Choosing it to be consistent.
	sfr := reqres.SecretListResponse{
		Secrets: secrets,
	}

	j.Event = audit.EventOk
	j.Entity = sfr
	audit.Log(j)

	resp, err := json.Marshal(sfr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := io.WriteString(w, "Problem unmarshaling response")
		if err != nil {
			log.InfoLn("List: Problem sending response", err.Error())
		}
		return
	}

	log.DebugLn("List: before response")

	_, err = io.WriteString(w, string(resp))
	if err != nil {
		log.InfoLn("Problem sending response", err.Error())
	}

	log.DebugLn("List: after response")
}
