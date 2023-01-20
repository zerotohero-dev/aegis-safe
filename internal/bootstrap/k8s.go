/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.z2h.dev>
 *     .\_/.
 */

package bootstrap

import (
	"context"
	"github.com/zerotohero-dev/aegis-safe/internal/log"
	"github.com/zerotohero-dev/aegis-safe/internal/state"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func persistKeys(privateKey, publicKey string) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.FatalLn("Error creating client config: %v", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.FatalLn("Error creating client: %v", err.Error())
	}

	data := make(map[string][]byte)
	keysCombined := privateKey + "\n" + publicKey
	data["KEY_TXT"] = ([]byte)(keysCombined)

	// Update the Secret in the cluster
	_, err = clientset.CoreV1().Secrets("aegis-system").Update(
		context.Background(),
		&v1.Secret{
			TypeMeta: metaV1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metaV1.ObjectMeta{
				Name:      "safe-age-key",
				Namespace: "aegis-system",
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
		log.FatalLn("error creating the secret", err.Error())
		return
	}

	log.InfoLn("Created the secret.")
	state.SetAgeKey(keysCombined)
	log.InfoLn("Registered the age key into memory.")
}

//recipient, err := age.ParseX25519Recipient(publicKey)
//if err != nil {
//	log.FatalLn("Failed to parse public key %q: %v", publicKey, err)
//}
//
//out := &bytes.Buffer{}
//
//w, err := age.Encrypt(out, recipient)
//if err != nil {
//	log.FatalLn("Failed to create encrypted file: %v", err)
//}
//
//if _, err := io.WriteString(w, "Black lives matter."); err != nil {
//	log.FatalLn("Failed to write to encrypted file: %v", err)
//}
//
//if err := w.Close(); err != nil {
//	log.FatalLn("Failed to close encrypted file: %v", err)
//}
//
//fmt.Printf("Encrypted file size: %d\n", out.Len())
//
//encrypted := out.String()
//
//log.InfoLn("encrypted", encrypted)
//
//identity, err = age.ParseX25519Identity(privateKey)
//if err != nil {
//	log.FatalLn("Failed to parse private key %q: %v", privateKey, err)
//}
//
//out = &bytes.Buffer{}
//f := bytes.NewReader(([]byte)(encrypted))
//
//r, err := age.Decrypt(f, identity)
//if err != nil {
//	log.FatalLn("Failed to open encrypted file: %v", err)
//}
//if _, err := io.Copy(out, r); err != nil {
//	log.FatalLn("Failed to read encrypted file: %v", err)
//}
//
//fmt.Printf("File contents: %q\n", out.Bytes())
