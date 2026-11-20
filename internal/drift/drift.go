// Package drift computes a deterministic remediation plan without changing live state.
package drift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/compiler"
)

type object = map[string]any

type Change struct {
	Action   string `json:"action"`
	Object   string `json:"object"`
	Expected object `json:"expected,omitempty"`
}

func key(o object) (string, error) {
	api, a := o["apiVersion"].(string)
	kind, b := o["kind"].(string)
	m, _ := o["metadata"].(object)
	name, c := m["name"].(string)
	namespace, _ := m["namespace"].(string)
	if namespace == "" && kind != "CiliumClusterwideNetworkPolicy" {
		namespace = "default"
	}
	if !a || !b || !c || api == "" || kind == "" || name == "" {
		return "", fmt.Errorf("object must have apiVersion, kind and metadata.name")
	}
	group, _, hasGroup := strings.Cut(api, "/")
	if !hasGroup {
		group = "core"
	}
	return strings.Join([]string{group, kind, namespace, name}, "/"), nil
}

func index(objects []object) (map[string]object, error) {
	result := make(map[string]object)
	for _, o := range objects {
		id, err := key(o)
		if err != nil {
			return nil, err
		}
		if result[id] != nil {
			return nil, fmt.Errorf("duplicate object %s", id)
		}
		result[id] = o
	}
	return result, nil
}

func managedFields(o object) ([]byte, error) {
	if o["kind"] == "ServiceAccount" {
		m, _ := o["metadata"].(object)
		a, _ := m["annotations"].(object)
		return json.Marshal(a["eks.amazonaws.com/role-arn"])
	}
	return json.Marshal(object{"spec": o["spec"], "specs": o["specs"]})
}

func relevant(o object) bool {
	switch o["kind"] {
	case "NetworkPolicy", "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "AuthorizationPolicy", "PeerAuthentication":
		return true
	case "ServiceAccount":
		m, _ := o["metadata"].(object)
		a, _ := m["annotations"].(object)
		return a["eks.amazonaws.com/role-arn"] != nil
	}
	return false
}

// Compare expects a complete, scope-filtered Kubernetes List supplied by the
// caller. Unexpected policies get a review action because ownership is unknown.
func Compare(expected compiler.Bundle, live []object) ([]Change, error) {
	want, err := index(expected.Kubernetes)
	if err != nil {
		return nil, err
	}
	got, err := index(live)
	if err != nil {
		return nil, err
	}
	changes := make([]Change, 0)
	for id, o := range want {
		action := "create"
		if current := got[id]; current != nil {
			a, err := managedFields(o)
			if err != nil {
				return nil, err
			}
			b, err := managedFields(current)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(a, b) {
				continue
			}
			action = "reconcile"
		}
		changes = append(changes, Change{action, id, o})
	}
	for id, o := range got {
		if want[id] == nil && relevant(o) {
			changes = append(changes, Change{"review-unexpected", id, nil})
		}
	}
	slices.SortFunc(changes, func(a, b Change) int { return strings.Compare(a.Object, b.Object) })
	return changes, nil
}
