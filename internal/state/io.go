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
	"encoding/json"
	"filippo.io/age"
	entity "github.com/zerotohero-dev/aegis-core/entity/data/v1"
	"github.com/zerotohero-dev/aegis-core/env"
	"github.com/zerotohero-dev/aegis-core/log"
	"io"
	"os"
	"path"
	"strings"
)

func ageKeyPair() (string, string) {
	if ageKey == "" {
		return "", ""
	}

	parts := strings.Split(ageKey, "\n")

	return parts[0], parts[1]
}

func readFromDisk(key string) *entity.SecretStored {
	dataPath := path.Join(env.SafeDataPath(), key+".age")

	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		log.TraceLn("readFromDisk: No file at:", dataPath)
		return nil
	}

	data, err := os.ReadFile(dataPath)
	if err != nil {
		log.WarnLn("readFromDisk: Error reading file:", err.Error())
		return nil
	}

	privateKey, _ := ageKeyPair()

	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.WarnLn("Failed to parse private key", privateKey, err)
	}

	if len(data) == 0 {
		log.WarnLn("file on disk appears to be empty")
		return nil
	}

	out := &bytes.Buffer{}
	f := bytes.NewReader(data)

	r, err := age.Decrypt(f, identity)
	if err != nil {
		log.WarnLn("Failed to open encrypted file", err.Error())
		return nil
	}

	if _, err := io.Copy(out, r); err != nil {
		log.WarnLn("Failed to read encrypted file", err.Error())
		return nil
	}

	contents := out.Bytes()

	var secret entity.SecretStored
	err = json.Unmarshal(contents, &secret)
	if err != nil {
		log.WarnLn("Failed to unmarshal secret", err.Error())
		return nil
	}
	return &secret
}

func persist(secret entity.SecretStored) {
	// Resetting the value also removes the secret file from the disk.
	if secret.Value == "" {
		dataPath := path.Join(env.SafeDataPath(), secret.Name+".age")
		err := os.Remove(dataPath)
		if !os.IsNotExist(err) {
			log.WarnLn("persist: failed to remove secret", err.Error())
		}
		return
	}

	data, err := json.Marshal(secret)
	if err != nil {
		log.WarnLn("persist: failed to marshal secret", err.Error())
		return
	}

	dataPath := path.Join(env.SafeDataPath(), secret.Name+".age")
	file, err := os.Create(dataPath)
	if err != nil {
		log.WarnLn("persist: problem creating file", err.Error())
		return
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
	}

	out := file

	w, err := age.Encrypt(out, recipient)
	if err != nil {
		log.WarnLn("Failed to create encrypted file", err.Error())
	}

	if _, err := io.WriteString(w, string(data)); err != nil {
		log.FatalLn("Failed to write to encrypted file: %v", err.Error())
	}
	defer func() {
		err := w.Close()
		if err != nil {
			log.InfoLn("problem closing stream", err.Error())
		}
	}()
}
