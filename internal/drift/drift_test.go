package drift

import (
	"encoding/json"
	"testing"

	"github.com/cuhawk/AegisMesh/internal/compiler"
)

func TestCompare(t *testing.T) {
	policy := func(name string, spec object) object {
		return object{"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": object{"name": name, "namespace": "app"}, "spec": spec}
	}
	expected := compiler.Bundle{Kubernetes: []object{policy("edge", object{"ingress": []object{{}}}), policy("worker", object{})}}
	data, err := json.Marshal(expected.Kubernetes)
	if err != nil {
		t.Fatal(err)
	}
	var live []object
	if err := json.Unmarshal(data, &live); err != nil {
		t.Fatal(err)
	}
	live[0]["status"] = object{"ready": true}
	live[0]["metadata"].(object)["resourceVersion"] = "17"
	changes, err := Compare(expected, live)
	if err != nil || len(changes) != 0 {
		t.Fatalf("unexpected drift: %v %v", changes, err)
	}
	live[0]["spec"] = object{"egress": []object{{"toEntities": []string{"world"}}}}
	live[1] = policy("stray", object{})
	changes, err = Compare(expected, live)
	if err != nil || len(changes) != 3 || changes[0].Action != "reconcile" || changes[1].Action != "review-unexpected" || changes[2].Action != "create" {
		t.Fatalf("wrong remediation plan: %v %v", changes, err)
	}
	if _, err = Compare(expected, append(live, live[0])); err == nil {
		t.Fatal("accepted ambiguous duplicate inventory object")
	}
}
