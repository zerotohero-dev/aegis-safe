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
	"github.com/zerotohero-dev/aegis-core/crypto"
	entity "github.com/zerotohero-dev/aegis-core/entity/data/v1"
	reqres "github.com/zerotohero-dev/aegis-core/entity/reqres/safe/v1"
	"github.com/zerotohero-dev/aegis-core/log"
	"github.com/zerotohero-dev/aegis-core/validation"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	"io"
	"net/http"
)

func Secret(w http.ResponseWriter, r *http.Request, svid string) {
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

	if !validation.IsSentinel(svid) {
		j.Event = AuditEventBadSvid
		audit(j)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Problem sending response", err.Error())
		}
		return
	}

	log.DebugLn("Secret: sentinel svid:", svid)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		j.Event = AuditEventBrokenBody
		audit(j)

		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Secret: Problem sending response", err.Error())
		}
		return
	}
	defer func(b io.ReadCloser) {
		if b == nil {
			return
		}
		err := b.Close()
		if err != nil {
			log.InfoLn("Secret: Problem closing body", err.Error())
		}
	}(r.Body)

	log.DebugLn("Secret: Parsed request body")

	var sr reqres.SecretUpsertRequest
	err = json.Unmarshal(body, &sr)
	if err != nil {
		j.Event = AuditEventRequestTypeMismatch
		audit(j)
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "")
		if err != nil {
			log.InfoLn("Secret: Problem sending response", err.Error())
		}
		return
	}

	j.Entity = sr

	workloadId := sr.WorkloadId
	value := sr.Value

	backingStore := sr.BackingStore
	useK8s := sr.UseKubernetes
	namespace := sr.Namespace
	template := sr.Template
	format := sr.Format
	encrypt := sr.Encrypt

	if namespace == "" {
		namespace = "default"
	}

	log.DebugLn("Secret:Upsert: ",
		"workloadId:", workloadId,
		"namespace:", namespace,
		"backingStore:", backingStore,
		"template:", template,
		"format:", format,
		"encrypt:", encrypt,
		"useK8s", useK8s)

	if workloadId == "" {
		j.Event = AuditEventNoWorkloadId
		audit(j)

		return
	}

	state.UpsertSecret(entity.SecretStored{
		Name: workloadId,
		Meta: entity.SecretMeta{
			UseKubernetesSecret: useK8s,
			Namespace:           namespace,
			BackingStore:        backingStore,
			Template:            template,
			Format:              format,
			Encrypted:           encrypt,
		},
		Value: value,
	})
	log.DebugLn("Secret:UpsertEnd: workloadId", workloadId)

	j.Event = AuditEventOk
	audit(j)

	_, err = io.WriteString(w, "OK")
	if err != nil {
		log.InfoLn("Secret: Problem sending response", err.Error())
	}
}
