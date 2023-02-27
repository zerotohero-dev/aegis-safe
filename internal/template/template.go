/*
 * .-'_.---._'-.
 * ||####|(__)||   Protect your secrets, protect your business.
 *   \\()|##//       Secure your sensitive data with Aegis.
 *    \\ |#//                  <aegis.ist>
 *     .\_/.
 */

package template

import (
	"bytes"
	"encoding/json"
	data "github.com/zerotohero-dev/aegis-core/entity/data/v1"
	"strings"
	"text/template"
)

func Parse(secret data.SecretStored) (map[string]string, error) {
	// jsonData := `{"user": "admin", "pass": "AegisRocks"}`
	// tmpStr := `{"USER":"{{.user}}", "PASS":"{{.pass}}"}`

	jsonData := strings.TrimSpace(secret.Value)
	tmpStr := strings.TrimSpace(secret.Meta.Template)

	secretData := make(map[string]string)
	err := json.Unmarshal([]byte(jsonData), &secretData)
	if err != nil {
		return secretData, err
	}

	if tmpStr == "" {
		return secretData, err
	}

	tmpl, err := template.New("secret").Parse(tmpStr)
	if err != nil {
		return secretData, err
	}

	var tpl bytes.Buffer
	err = tmpl.Execute(&tpl, secretData)
	if err != nil {
		return secretData, err
	}

	output := make(map[string]string)
	err = json.Unmarshal(tpl.Bytes(), &output)
	if err != nil {
		return output, err
	}

	return output, nil
}
