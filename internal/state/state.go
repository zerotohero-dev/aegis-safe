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
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/log"
	"sync"
	"time"
)

// This is where all the secrets are stored.
var secrets sync.Map

const selfName = "aegis-safe"

type AegisInternalCommand struct {
	LogLevel int `json:"logLevel"`
}

var ageKey = ""
var lock sync.Mutex

func SetAgeKey(k string) {
	lock.Lock()
	defer lock.Unlock()
	ageKey = k
}

func evaluate(data string) *AegisInternalCommand {
	var command AegisInternalCommand
	err := json.Unmarshal([]byte(data), &command)
	if err != nil {
		return nil
	}
	return &command
}

// These are persisted to files. They are buffered, so that they can
// be written in the order they are queued and there are no concurrent
// writes to the same file at a time. An alternative approach would be
// to have a map of queues of `SecretsStored`s per file name but that
// feels like an overkill.
var secretQueue = make(chan entity.SecretStored, env.SafeSecretBufferSize())

func handleSecrets() {
	for {
		secret := <-secretQueue
		persist(secret)
	}
}

func init() {
	go handleSecrets()
}

type StoreType string

var Persistent StoreType = "persistent"

func UpsertSecret(secret entity.SecretStored) {
	if secret.Name == selfName {
		cmd := evaluate(secret.Value)
		if cmd != nil {
			newLogLevel := cmd.LogLevel
			log.InfoLn("Setting new level to:", newLogLevel)
			log.SetLevel(log.Level(newLogLevel))
		}
	}

	s, exists := secrets.Load(secret.Name)
	now := time.Now()
	if exists {
		ss := s.(entity.SecretStored)
		secret.Created = ss.Created
	} else {
		secret.Created = now
	}
	secret.Updated = now

	log.InfoLn("UpsertSecret:",
		"created", secret.Created, "updated", secret.Updated, "name", secret.Name,
	)

	if secret.Value == "" {
		secrets.Delete(secret.Name)
	} else {
		secrets.Store(secret.Name, secret)
	}

	store := env.SafeBackingStoreType()
	if store == string(Persistent) {
		secretQueue <- secret
	}
}

func ReadSecret(key string) *entity.SecretStored {
	result, ok := secrets.Load(key)
	if !ok {
		stored := readFromDisk(key)
		if stored == nil {
			return nil
		}
		go persist(*stored)
		secrets.Store(stored.Name, *stored)
		return stored
	}

	s := result.(entity.SecretStored)
	return &s
}
