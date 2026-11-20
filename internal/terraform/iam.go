// Package terraform renders exact AWS IAM grants as Terraform JSON configuration.
package terraform

import (
	"encoding/json"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

type Object = map[string]any

type Statement struct {
	Effect    string   `json:"Effect"`
	Action    []string `json:"Action"`
	Resource  []string `json:"Resource,omitempty"`
	Principal Object   `json:"Principal,omitempty"`
	Condition Object   `json:"Condition,omitempty"`
}

type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

func document(statements ...Statement) Policy {
	return Policy{"2012-10-17", statements}
}

// Render produces replacement policy documents and role configuration. Existing
// roles must be imported, and unrelated wildcard policies removed during migration.
func Render(in intent.Intent) (Object, map[string]Policy, error) {
	resources := make(map[string]intent.Resource)
	for _, r := range in.Resources {
		resources[r.ID] = r
	}
	reads := make(map[string][]Statement)
	trust := make(map[string][]Statement)
	for _, r := range in.Rules {
		if r.Deny {
			continue
		}
		switch r.Kind {
		case "read":
			reads[r.From] = append(reads[r.From], Statement{
				Effect: "Allow", Action: []string{r.Action}, Resource: []string{resources[r.To].Value},
				Condition: Object{"Bool": Object{"aws:SecureTransport": "true"}},
			})
		case "assume":
			issuer := strings.SplitN(r.OIDCProvider, "oidc-provider/", 2)[1]
			trust[r.To] = append(trust[r.To], Statement{
				Effect: "Allow", Action: []string{r.Action},
				Principal: Object{"Federated": r.OIDCProvider},
				Condition: Object{"StringEquals": Object{issuer + ":aud": r.Audience, issuer + ":sub": r.Subject}},
			})
		}
	}
	roles, inline := Object{}, Object{}
	account := ""
	policies := make(map[string]Policy)
	for _, r := range in.Resources {
		if r.Kind != "role" {
			continue
		}
		if len(trust[r.ID]) == 0 {
			continue
		}
		account = strings.Split(r.Value, ":")[4]
		rolePath := strings.SplitN(r.Value, ":role/", 2)[1]
		i := strings.LastIndex(rolePath, "/")
		address := strings.ReplaceAll(r.ID, "-", "_")
		policy := document(trust[r.ID]...)
		policies[r.ID+"-trust"] = policy
		value, err := json.Marshal(policy)
		if err != nil {
			return nil, nil, err
		}
		roles[address] = Object{
			"name": rolePath[i+1:], "path": "/" + rolePath[:i+1], "assume_role_policy": string(value),
			"max_session_duration": 3600,
		}
		if len(reads[r.ID]) > 0 {
			policy := document(reads[r.ID]...)
			policies[r.ID+"-access"] = policy
			value, err := json.Marshal(policy)
			if err != nil {
				return nil, nil, err
			}
			inline[address] = Object{
				"name": "aegismesh", "role": "${aws_iam_role." + address + ".name}", "policy": string(value),
			}
		}
	}
	config := Object{
		"terraform": Object{"required_providers": Object{"aws": Object{"source": "hashicorp/aws", "version": "~> 6.0"}}},
		"resource":  Object{"aws_iam_role": roles, "aws_iam_role_policy": inline},
	}
	if account != "" {
		config["provider"] = Object{"aws": Object{"allowed_account_ids": []string{account}}}
	}
	return config, policies, nil
}
