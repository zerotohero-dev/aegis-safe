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
	"github.com/zerotohero-dev/aegis-core/crypto"
	reqres "github.com/zerotohero-dev/aegis-core/entity/reqres/v1"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/log"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	"github.com/zerotohero-dev/aegis/core/validation"
	"io"
	"net/http"
	"strings"
)

func List(w http.ResponseWriter, r *http.Request, svid string) {
	correlationId, _ := crypto.RandomString(8)
	if correlationId == "" {
		correlationId = "CID"
	}

	j := JournalEntry{
		CorrelationId: correlationId,
		Entity:        nil,
		Method:        r.Method,
		Url:           r.RequestURI,
		Svid:          svid,
		Event:         AuditEventEnter,
	}

	audit(j)

	// Only sentinel can list.
	if !validation.IsSentinel(svid) {
		j.Event = AuditEventBadSvid
		audit(j)

		log.DebugLn("List: bad svid", svid)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("List: Problem sending response")
		}

		return
	}

	log.DebugLn("List: sending response")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		j.Event = AuditEventBrokenBody
		audit(j)

		w.WriteHeader(http.StatusBadRequest)

		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("List: Problem sending response")
		}

		return
	}

	log.DebugLn("List: sent response")

	defer func() {
		err := r.Body.Close()
		if err != nil {
			log.InfoLn("List: Problem closing body")
		}
	}()

	log.DebugLn("List: preparing request")

	var sr reqres.SecretListRequest
	err = json.Unmarshal(body, &sr)
	if err != nil {
		j.Event = AuditEventRequestTypeMismatch
		audit(j)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("List: Problem sending response", err.Error())
		}
		return
	}

	j.Entity = sr

	log.DebugLn("List: prepared request")

	tmp := strings.Replace(svid, env.SentinelSvidPrefix(), "", 1)
	parts := strings.Split(tmp, "/")
	if len(parts) == 0 {
		j.Event = AuditEventBadPeerSvid
		audit(j)

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

	j.Event = AuditEventOk
	j.Entity = sfr
	audit(j)

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
