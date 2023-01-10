/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package state

import (
	"sync"
)

// This is where all the secrets are stored.
var secrets sync.Map

func UpsertSecret(id, data string) {
	secrets.Store(id, data)
}

func ReadSecret(key string) string {
	result, ok := secrets.Load(key)
	if !ok {
		return ""
	}

	return result.(string)
}
