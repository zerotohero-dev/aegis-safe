/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package validation

import (
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zerotohero-dev/aegis-core/log"
	"github.com/zerotohero-dev/aegis/core/validation"
)

func EnsureSelfSPIFFEID(source *workloadapi.X509Source) {
	if source == nil {
		log.FatalLn("Could not find source")
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		log.FatalLn("Unable to get X.509 SVID from source bundle:", err.Error())
	}

	svidId := svid.ID
	if !validation.IsSafe(svid.ID.String()) {
		log.FatalLn(
			"Svid check: I don’t know you, and it’s crazy:", svidId.String(),
		)
	}
}
