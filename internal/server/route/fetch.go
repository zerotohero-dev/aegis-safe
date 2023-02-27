/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.ist>
 *     .\_/.
 */

package route

import (
	"encoding/json"
	"fmt"
	"github.com/zerotohero-dev/aegis-core/crypto"
	reqres "github.com/zerotohero-dev/aegis-core/entity/reqres/safe/v1"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/log"
	"github.com/zerotohero-dev/aegis-core/validation"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	"io"
	"net/http"
	"strings"
	"time"
)

func Fetch(w http.ResponseWriter, r *http.Request, svid string) {
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

	// Only workloads can fetch.
	if !validation.IsWorkload(svid) {
		j.Event = AuditEventBadSvid
		audit(j)

		log.DebugLn("Fetch: bad svid", svid)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response", err.Error())
		}

		return
	}

	log.DebugLn("Fetch: sending response")

	defer func() {
		err := r.Body.Close()
		if err != nil {
			log.InfoLn("Fetch: Problem closing body")
		}
	}()

	log.DebugLn("Fetch: preparing request")

	tmp := strings.Replace(svid, env.WorkloadSvidPrefix(), "", 1)
	parts := strings.Split(tmp, "/")
	if len(parts) == 0 {
		j.Event = AuditEventBadPeerSvid
		audit(j)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem with svid", svid)
		}
		return
	}

	workloadId := parts[0]
	secret := state.ReadSecret(workloadId)

	log.TraceLn("Fetch: workloadId", workloadId)

	// If secret does not exist, send an empty response.
	if secret == nil {
		j.Event = AuditEventNoSecret
		audit(j)

		w.WriteHeader(http.StatusNotFound)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response", err.Error())
		}
		return
	}

	log.DebugLn("Fetch: will send. workload id:", workloadId)

	// TODO: if the secret has a transformation, set `Data:` as the transformed secret value.
	// if secret.Meta.Template != "" {
	// 	val, err := parse(*secret)
	//	if err != nil {
	//		secret.Value = val
	//	}
	// }

	// RFC3339 is what Go uses internally when marshaling dates.
	// Choosing it to be consistent.
	sfr := reqres.SecretFetchResponse{
		Data:    secret.Value,
		Created: fmt.Sprintf("\"%s\"", secret.Created.Format(time.RFC3339)),
		Updated: fmt.Sprintf("\"%s\"", secret.Updated.Format(time.RFC3339)),
	}

	j.Event = AuditEventOk
	j.Entity = sfr
	audit(j)

	resp, err := json.Marshal(sfr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := io.WriteString(w, "Problem unmarshaling response")
		if err != nil {
			log.InfoLn("Fetch: Problem sending response", err.Error())
		}
		return
	}

	log.DebugLn("Fetch: before response")

	_, err = io.WriteString(w, string(resp))
	if err != nil {
		log.InfoLn("Problem sending response", err.Error())
	}

	log.DebugLn("Fetch: after response")
}
