/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package state

import (
	"encoding/json"
	entity "github.com/zerotohero-dev/aegis-core/entity/data/v1"
	"github.com/zerotohero-dev/aegis-safe/internal/log"
	"sync"
	"time"
)

// This is where all the secrets are stored.
var secrets sync.Map

const selfName = "aegis-safe"

type AegisInternalCommand struct {
	LogLevel int `json:"logLevel"`
}

func evaluate(data string) *AegisInternalCommand {
	var command AegisInternalCommand
	err := json.Unmarshal([]byte(data), &command)
	if err != nil {
		return nil
	}
	return &command
}

func UpsertSecret(secret entity.SecretStored) {
	if secret.Name == selfName {
		cmd := evaluate(secret.Value)
		if cmd != nil {
			newLogLevel := cmd.LogLevel
			log.InfoLn("Setting new level to:", newLogLevel)
			log.SetLevel(log.Level(newLogLevel))
		}
	}

	_, exists := secrets.Load(secret.Name)
	now := time.Now()
	if !exists {
		secret.Created = now
	}
	secret.Updated = now

	secrets.Store(secret.Name, secret)
}

func ReadSecret(key string) *entity.SecretStored {
	result, ok := secrets.Load(key)
	if !ok {
		return nil
	}

	s := result.(entity.SecretStored)
	return &s
}
