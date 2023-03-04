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
	"gopkg.in/yaml.v3"
	"strings"
	"text/template"
)

func validJSON(s string) bool {
	var js map[string]interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}

func jsonToYaml(js string) (string, error) {
	var jsonObj interface{}
	err := json.Unmarshal([]byte(js), &jsonObj)
	if err != nil {
		return "", err
	}
	yamlBytes, err := yaml.Marshal(jsonObj)
	if err != nil {
		return "", err
	}
	return string(yamlBytes), nil
}

func Parse(secret data.SecretStored) (string, error) {
	jsonData := strings.TrimSpace(secret.Value)
	tmpStr := strings.TrimSpace(secret.Meta.Template)

	if tmpStr == "" {
		return jsonData, nil
	}

	tmpl, err := template.New("secret").Parse(tmpStr)
	if err != nil {
		return jsonData, err
	}

	var tpl bytes.Buffer
	err = tmpl.Execute(&tpl, jsonData)
	if err != nil {
		return jsonData, err
	}

	parsedString := tpl.String()

	switch secret.Meta.Format {
	case data.None:
		return parsedString, nil
	case data.Json:
		if validJSON(parsedString) {
			return parsedString, nil
		} else {
			return jsonData, nil
		}
	case data.Yaml:
		if validJSON(parsedString) {
			yml, err := jsonToYaml(parsedString)
			if err != nil {
				return "", err
			}
			return yml, nil
		} else {
			return "", nil
		}
	}

	// Unknown option.
	return "", nil
}

// ParseForK8sSecret parses the provided `SecretStored` and applies a template
// if one is defined.
//
// Args:
//
//	secret: A SecretStored struct containing the secret data and metadata.
//
// Returns:
//
//	A map of string keys to string values, containing the parsed secret data.
//
//	If there is an error during parsing or applying the template, an error
//	will be returned.
func ParseForK8sSecret(secret data.SecretStored) (map[string]string, error) {
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
