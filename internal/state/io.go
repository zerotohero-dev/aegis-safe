/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package state

import (
	"bytes"
	"context"
	"encoding/json"
	"filippo.io/age"
	"github.com/pkg/errors"
	entity "github.com/zerotohero-dev/aegis-core/entity/data/v1"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/log"
	"io"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

func ageKeyPair() (string, string) {
	if ageKey == "" {
		return "", ""
	}

	parts := strings.Split(ageKey, "\n")

	return parts[0], parts[1]
}

func decryptDataFromDisk(key string) ([]byte, error) {
	dataPath := path.Join(env.SafeDataPath(), key+".age")

	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		log.TraceLn("decryptDataFromDisk: No file at:", dataPath)
		return nil, err
	}

	data, err := os.ReadFile(dataPath)
	if err != nil {
		log.WarnLn("decryptDataFromDisk: Error reading file:", err.Error())
		return nil, err
	}

	privateKey, _ := ageKeyPair()

	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.WarnLn("Failed to parse private key", privateKey, err)
		return nil, err
	}

	if len(data) == 0 {
		log.WarnLn("file on disk appears to be empty")
		return nil, err
	}

	out := &bytes.Buffer{}
	f := bytes.NewReader(data)

	r, err := age.Decrypt(f, identity)
	if err != nil {
		log.WarnLn("Failed to open encrypted file", err.Error())
		return nil, err
	}

	if _, err := io.Copy(out, r); err != nil {
		log.WarnLn("Failed to read encrypted file", err.Error())
		return nil, err
	}

	return out.Bytes(), nil
}

func readFromDisk(key string) *entity.SecretStored {
	contents, err := decryptDataFromDisk(key)
	if err != nil {
		return nil
	}

	var secret entity.SecretStored
	err = json.Unmarshal(contents, &secret)
	if err != nil {
		log.WarnLn("Failed to unmarshal secret", err.Error())
		return nil
	}
	return &secret
}

var lastBackedUpIndex = make(map[string]int)

func saveSecretToDisk(secret entity.SecretStored, dataPath string) error {
	data, err := json.Marshal(secret)
	if err != nil {
		log.WarnLn("persist: failed to marshal secret", err.Error())
		return err
	}

	file, err := os.Create(dataPath)
	if err != nil {
		log.WarnLn("persist: problem creating file", err.Error())
		return err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.InfoLn("problem closing file", err.Error())
		}
	}()

	_, publicKey := ageKeyPair()
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		log.WarnLn("Failed to parse public key", publicKey, err.Error())
		return err
	}

	out := file

	w, err := age.Encrypt(out, recipient)
	if err != nil {
		log.WarnLn("Failed to create encrypted file", err.Error())
		return err
	}

	if _, err := io.WriteString(w, string(data)); err != nil {
		log.FatalLn("Failed to write to encrypted file: %v", err.Error())
		return err
	}

	defer func() {
		err := w.Close()
		if err != nil {
			log.InfoLn("problem closing stream", err.Error())
		}
	}()

	return nil
}

const initialSecretValue = "{}"

func saveSecretToKubernetes(secret entity.SecretStored) error {
	// updates the Kubernetes Secret assuming it already exists.

	config, err := rest.InClusterConfig()
	if err != nil {
		return errors.Wrap(err, "could not create client config")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "could not create client")
	}

	data := make(map[string][]byte)
	value := secret.Value
	data["VALUE"] = ([]byte)(value)

	// Update the Secret in the cluster
	_, err = clientset.CoreV1().Secrets(secret.Meta.Namespace).Update(
		context.Background(),
		&v1.Secret{
			TypeMeta: metaV1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metaV1.ObjectMeta{
				Name:      "aegis-secret-" + secret.Name,
				Namespace: secret.Meta.Namespace,
			},
			Data: data,
		},
		metaV1.UpdateOptions{
			TypeMeta: metaV1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
		},
	)

	if err != nil {
		return errors.Wrap(err, "error updating the secret")
	}

	log.InfoLn("Created the secret.")
	return nil
}

func persistK8s(secret entity.SecretStored, errChan chan<- error) {
	// If the secret is empty, reset the corresponding Kubernetes Secret
	// to the initial secret value.
	if secret.Value == "" {
		secret.Value = initialSecretValue
	}

	err := saveSecretToKubernetes(secret)
	if err != nil {
		// Retry once more.
		time.Sleep(500 * time.Millisecond)
		err := saveSecretToKubernetes(secret)
		if err != nil {
			errChan <- err
		}
	}
}

// Only one goroutine accesses this function at any given time.
func persist(secret entity.SecretStored, errChan chan<- error) {
	backupCount := env.SafeSecretBackupCount()

	// Resetting the value also removes the secret file from the disk.
	if secret.Value == "" {
		dataPath := path.Join(env.SafeDataPath(), secret.Name+".age")
		err := os.Remove(dataPath)
		if !os.IsNotExist(err) {
			log.WarnLn("persist: failed to remove secret", err.Error())
		}
		return
	}

	// Save the secret
	dataPath := path.Join(env.SafeDataPath(), secret.Name+".age")

	err := saveSecretToDisk(secret, dataPath)
	if err != nil {
		// Retry once more.
		time.Sleep(500 * time.Millisecond)
		err := saveSecretToDisk(secret, dataPath)
		if err != nil {
			errChan <- err
		}
	}

	index, found := lastBackedUpIndex[secret.Name]
	if !found {
		lastBackedUpIndex[secret.Name] = 0
		index = 0
	}

	newIndex := math.Mod(float64(index+1), float64(backupCount))

	// Save a copy
	dataPath = path.Join(
		env.SafeDataPath(),
		secret.Name+"-"+strconv.Itoa(int(newIndex))+"-"+".age",
	)

	err = saveSecretToDisk(secret, dataPath)
	if err != nil {
		// Retry once more.
		time.Sleep(500 * time.Millisecond)
		err := saveSecretToDisk(secret, dataPath)
		if err != nil {
			errChan <- err
			// Do not change lastBackedUpIndex
			// since the backup was not successful.
			return
		}
	}

	lastBackedUpIndex[secret.Name] = int(newIndex)
}
