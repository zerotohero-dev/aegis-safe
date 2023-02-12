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

// The secrets put here are synced with their Kubernetes Secret counterparts.
var k8sSecretQueue = make(chan entity.SecretStored, env.SafeSecretBufferSize())

func handleSecrets() {
	errChan := make(chan error)

	go func() {
		// If the `persist` operation spews out an error, log it.
		e := <-errChan
		log.ErrorLn("handleSecrets: error persisting secret:", e.Error())
	}()

	for {
		// Get a secret to be persisted to the disk.
		secret := <-secretQueue

		// Persist the secret to disk.
		//
		// Each secret is persisted one at a time, with the order they
		// come in.
		//
		// Do not call this function elsewhere.
		// It is meant to be called inside this `handleSecrets` goroutine.
		persist(secret, errChan)
	}
}

func handleK8sSecrets() {
	errChan := make(chan error)

	go func() {
		// If the `persistK8s` operation spews out an error, log it.
		e := <-errChan
		log.ErrorLn("handleSecrets: error persisting secret:", e.Error())
	}()

	for {
		// Get a secret to be persisted to the disk.
		secret := <-k8sSecretQueue

		// Sync up the secret to etcd as a Kubernetes Secret.
		//
		// Each secret is synced one at a time, with the order they
		// come in.
		//
		// Do not call this function elsewhere.
		// It is meant to be called inside this `handleK8sSecrets` goroutine.
		persistK8s(secret, errChan)
	}
}

func init() {
	go handleSecrets()
	go handleK8sSecrets()
}

type StoreType string

var Persistent StoreType = "persistent"

func AllSecrets() []entity.Secret {
	var result []entity.Secret
	secrets.Range(func(key any, value any) bool {
		v := value.(entity.SecretStored)

		result = append(result, entity.Secret{
			Name:    v.Name,
			Created: entity.JsonTime(v.Created),
			Updated: entity.JsonTime(v.Updated),
		})

		return true
	})
	if result == nil {
		return []entity.Secret{}
	}
	return result
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

	store := secret.Meta.BackingStore

	switch store {
	case entity.File:
		secretQueue <- secret
	case entity.Cluster:
		panic("Cluster backing store not implemented yet!")
	}

	useK8sSecrets := secret.Meta.UseKubernetesSecret
	if useK8sSecrets {
		k8sSecretQueue <- secret
	}
}

func ReadSecret(key string) *entity.SecretStored {
	result, ok := secrets.Load(key)
	if !ok {
		stored := readFromDisk(key)
		if stored == nil {
			return nil
		}
		secrets.Store(stored.Name, *stored)
		secretQueue <- *stored
		return stored
	}

	s := result.(entity.SecretStored)
	return &s
}
