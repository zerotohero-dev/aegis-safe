/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package route

import (
	reqres "github.com/zerotohero-dev/aegis-core/entity/reqres/safe/v1"
	"github.com/zerotohero-dev/aegis-core/log"
)

type JournalEntry struct {
	CorrelationId string
	Entity        any
	Method        string
	Url           string
	Svid          string
	Event         AuditEvent
}

type AuditEvent string

var AuditEventEnter AuditEvent = "aegis-enter"
var AuditEventBadSvid AuditEvent = "aegis-bad-svid"
var AuditEventBrokenBody AuditEvent = "aegis-broken-body"
var AuditEventRequestTypeMismatch AuditEvent = "aegis-request-type-mismatch"
var AuditEventBadPeerSvid AuditEvent = "aegis-bad-peer-svid"
var AuditEventNoSecret AuditEvent = "aegis-no-secret"
var AuditEventOk AuditEvent = "aegis-ok"
var AuditEventNoWorkloadId AuditEvent = "aegis-no-workload-id"

func printAudit(correlationId, method, url, svid, message string) {
	log.InfoLn(
		correlationId,
		"method", method,
		"url", url,
		"svid", svid,
		"msg", message,
	)
}

func audit(e JournalEntry) {
	if e.Entity == nil {
		printAudit(
			e.CorrelationId,
			e.Method, e.Url, e.Svid, string(e.Event),
		)
	}

	switch v := e.Entity.(type) {
	case reqres.SecretFetchRequest:
		printAudit(
			e.CorrelationId,
			e.Method, e.Url, e.Svid,
			"e:"+v.Err+"m"+string(e.Event),
		)
	case reqres.SecretFetchResponse:
		printAudit(
			e.CorrelationId,
			e.Method, e.Url, e.Svid,
			"e:"+v.Err+"c:"+v.Created+"u:"+v.Updated+"m:"+string(e.Event),
		)
	}
}
