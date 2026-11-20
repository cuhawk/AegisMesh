// Package intent defines the declarative inputs to the compiler and prover.
package intent

import (
	"encoding/json"
	"fmt"
	"io"
)

type Intent struct {
	SPIREParent string     `json:"spireParent"`
	TrustDomain string     `json:"trustDomain"`
	Workloads   []Workload `json:"workloads"`
	Resources   []Resource `json:"resources"`
	Rules       []Rule     `json:"rules"`
	NeverReach  []Pair     `json:"neverReach"`
}

type Workload struct {
	ID             string `json:"id"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	Tenant         string `json:"tenant"`
	SVIDTTL        int    `json:"svidTTL"`
	Ingress        bool   `json:"ingress,omitempty"`
	Untrusted      bool   `json:"untrusted,omitempty"`
}

type Resource struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"` // fqdn, vault, object, role, metadata, internet, cidr
	Value string `json:"value"`
}

type Pair struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Rule struct {
	Pair
	Kind           string `json:"kind"` // http, dns, read, assume, pass, proxy, redirect
	Deny           bool   `json:"deny,omitempty"`
	Port           int    `json:"port,omitempty"`
	Method         string `json:"method,omitempty"`
	Path           string `json:"path,omitempty"`
	Action         string `json:"action,omitempty"`
	OIDCProvider   string `json:"oidcProvider,omitempty"`
	Audience       string `json:"audience,omitempty"`
	Subject        string `json:"subject,omitempty"`
	ApprovedEgress bool   `json:"approvedEgress,omitempty"`
}

func Decode(r io.Reader) (Intent, error) {
	var in Intent
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return in, err
	}
	var trailing json.RawMessage
	if err := d.Decode(&trailing); err != io.EOF {
		return in, fmt.Errorf("expected one intent document")
	}
	return in, nil
}
