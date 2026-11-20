"""Validate the example against pinned upstream schemas and the emitted gate."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
from urllib.request import urlopen

import jsonschema
import yaml

CILIUM = "https://raw.githubusercontent.com/cilium/cilium/v1.19.6/pkg/k8s/apis/cilium.io/client/crds/v2/"
ISTIO = "https://raw.githubusercontent.com/istio/istio/1.31.4/manifests/charts/base/files/crd-all.gen.yaml"
GATEWAY = "https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.3.0/config/crd/standard/"
KUBERNETES = (
    "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/"
    "88b0235585da4efb0e4bc6cc00baccf0e327e54d/v1.33.0-standalone-strict/"
)


def fetch(url):
    with urlopen(url, timeout=30) as response:
        return response.read().decode()


def crd_schemas(url):
    for doc in yaml.safe_load_all(fetch(url)):
        if doc and doc.get("kind") == "CustomResourceDefinition":
            spec = doc["spec"]
            for ver in spec["versions"]:
                if ver.get("served"):
                    yield (spec["group"] + "/" + ver["name"], spec["names"]["kind"]), ver["schema"]["openAPIV3Schema"]


def validate_gate(artifact_dir, original):
    gate = artifact_dir / "gate.rego"
    subprocess.run(["opa", "check", "--strict", gate], check=True)

    def evaluate(data, expected, case):
        result = subprocess.run(
            ["opa", "eval", "--format=raw", "--stdin-input", "-d", gate, "data.aegismesh.allow"],
            input=json.dumps(data), capture_output=True, text=True, check=True,
        )
        assert result.stdout.strip() == expected, (case, result.stdout, result.stderr)

    evaluate(original, "true", "clean bundle")
    mutations = [
        lambda b: b["kubernetes"][0]["spec"]["egressDeny"][0]["toCIDR"].remove("169.254.169.254/32"),
        lambda b: b["iam"]["reader-role-access"]["Statement"][0].update(Action=["s3:*"]),
        lambda b: b["iam"]["reader-role-access"]["Statement"][0].update(Resource=["*"]),
        lambda b: b["iam"]["reader-role-trust"]["Statement"][0].pop("Condition"),
        lambda b: b["spire"][0].update(x509_svid_ttl=3601),
        lambda b: b["terraform"]["resource"]["aws_iam_role_policy"]["reader_role"].update(policy="{}"),
        lambda b: b["ciliumHTTP"][0]["spec"]["egressDeny"][0]["toCIDR"].remove("fd00:ec2::254/128"),
        lambda b: next(x for x in b["kubernetes"] if x["kind"] == "PeerAuthentication")["spec"].update(mtls={"mode": "PERMISSIVE"}),
        lambda b: next(x for x in b["kubernetes"] if x["kind"] == "AuthorizationPolicy")["spec"].update(rules=[{}]),
    ]
    if original.get("toolAuthorizations"):
        def tool_policy(bundle, kind):
            name = bundle["toolAuthorizations"][0]["tool"]
            return next(x for x in bundle["kubernetes"] if x["kind"] == kind and x["metadata"]["name"] == name)

        def route(bundle):
            return next(x for x in bundle["kubernetes"] if x["kind"] == "HTTPRoute")

        mutations.extend([
            lambda b: tool_policy(b, "AuthorizationPolicy")["spec"]["rules"][0].pop("when"),
            lambda b: tool_policy(b, "AuthorizationPolicy")["spec"]["rules"][0]["when"].pop(),
            lambda b: tool_policy(b, "RequestAuthentication")["spec"]["jwtRules"][0].pop("audiences"),
            lambda b: b.pop("toolAuthorizations"),
            lambda b: next(x for x in b["kubernetes"] if x["kind"] == "ReferenceGrant")["spec"]["to"][0].pop("name"),
            lambda b: b.update(ciliumHTTP=[x for x in b["ciliumHTTP"] if x["kind"] != "ReferenceGrant"]),
            lambda b: route(b)["spec"]["rules"][0]["backendRefs"][0].update(namespace="wrong"),
            lambda b: route(b)["spec"]["rules"][0]["matches"][0]["path"].update(type="PathPrefix"),
        ])
    for number, mutate in enumerate(mutations, 1):
        altered = copy.deepcopy(original)
        mutate(altered)
        evaluate(altered, "false", number)
        result = subprocess.run(
            ["opa", "eval", "--format=raw", "--stdin-input", "-d", gate, "data.aegismesh.deny"],
            input=json.dumps(altered), capture_output=True, text=True, check=True,
        )
        assert json.loads(result.stdout), (number, "missing Rego denial witness")
    return len(mutations)


def validate_tool_requests(artifact_dir, bundle):
    if not bundle.get("toolAuthorizations"):
        return 0, 0
    data = artifact_dir / "tool-authorization-data.json"
    edges = json.loads(data.read_text())["aegismesh_tool_authorizations"]
    assert edges == bundle["toolAuthorizations"]
    edge = edges[0]
    request = {key: edge[key] for key in ("namespace", "tool", "method", "path", "port")}
    request["peer_principal"] = edge["principal"]
    request["claims"] = {
        "iss": edge["issuer"], "sub": edge["subject"], "aud": [edge["audience"]],
        "model_id": edge["model_id"], "tool_scopes": [edge["tool_scope"]],
        "delegator_sub": edge["delegator_sub"],
    }

    def evaluate(value, allowed):
        result = subprocess.run(
            ["opa", "eval", "--format=raw", "--stdin-input", "-d", artifact_dir / "gate.rego",
             "-d", data, "data.aegismesh.allow_tool"],
            input=json.dumps(value), capture_output=True, text=True, check=True,
        )
        assert result.stdout.strip() == str(allowed).lower(), (value, result.stdout, result.stderr)

    evaluate(request, True)
    scalar = copy.deepcopy(request)
    scalar["claims"]["aud"] = edge["audience"]
    evaluate(scalar, True)
    mutations = [
        lambda r: r.update(peer_principal="cluster.local/ns/research/sa/other"),
        lambda r: r.update(path="/admin"),
        lambda r: r.update(method="GET"),
        lambda r: r.update(port="80"),
        lambda r: r.update(namespace="default"),
        lambda r: r["claims"].pop("model_id"),
        lambda r: r["claims"].update(model_id="other-model"),
        lambda r: r["claims"].update(tool_scopes=["other-scope"]),
        lambda r: r["claims"].update(tool_scopes=edge["tool_scope"]),
        lambda r: r["claims"].update(delegator_sub="spiffe://cluster.local/other"),
        lambda r: r["claims"].update(sub="spiffe://cluster.local/other"),
        lambda r: r["claims"].update(aud=["other-tool"]),
        lambda r: r["claims"].update(iss="https://other.example.com"),
    ]
    for mutate in mutations:
        altered = copy.deepcopy(request)
        mutate(altered)
        evaluate(altered, False)
    return len(mutations), 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--example", default="multitenant.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    schema = json.loads((root / "schemas/intent.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(json.loads((root / "examples" / args.example).read_text()), schema)

    schemas = dict(crd_schemas(CILIUM + "ciliumnetworkpolicies.yaml"))
    schemas.update(crd_schemas(CILIUM + "ciliumclusterwidenetworkpolicies.yaml"))
    schemas.update(crd_schemas(ISTIO))
    schemas["v1", "ServiceAccount"] = json.loads(fetch(KUBERNETES + "serviceaccount-v1.json"))
    bundle = json.loads((args.directory / "bundle.json").read_text())
    if any(o["kind"] == "HTTPRoute" for o in bundle["kubernetes"]):
        for kind in ("httproutes", "referencegrants"):
            schemas.update(crd_schemas(GATEWAY + f"gateway.networking.k8s.io_{kind}.yaml"))
    count = 0
    for filename, field in [("kubernetes.yaml", "kubernetes"), ("cilium-http.yaml", "ciliumHTTP")]:
        objects = list(yaml.safe_load_all((args.directory / filename).read_text()))
        assert objects == bundle[field], filename
        for obj in objects:
            jsonschema.Draft7Validator(schemas[obj["apiVersion"], obj["kind"]]).validate(obj)
            count += 1

    # Exercise the drift command using an export shaped like kubectl's List.
    live = args.directory / "verified-live.json"
    live.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": bundle["kubernetes"]}))

    entries = json.loads((args.directory / "spire-entries.json").read_text())["entries"]
    assert entries == bundle["spire"]
    assert all(0 < entry["x509_svid_ttl"] <= 3600 and len(entry["selectors"]) == 2 for entry in entries)
    terraform = json.loads((args.directory / "iam.tf.json").read_text())
    assert terraform == bundle["terraform"]
    for role, entry in terraform["resource"]["aws_iam_role"].items():
        slug = role.replace("_", "-")
        assert json.loads(entry["assume_role_policy"]) == bundle["iam"][slug + "-trust"]
        inline = terraform["resource"]["aws_iam_role_policy"].get(role)
        if inline:
            assert json.loads(inline["policy"]) == bundle["iam"][slug + "-access"]
    migration = (args.directory / "iam.tf.json.diff").read_text()
    assert any(line.startswith("-") and "s3:*" in line for line in migration.splitlines())
    assert any(line.startswith("+") and "s3:GetObject" in line for line in migration.splitlines())
    rejections = validate_gate(args.directory, bundle)
    denied, allowed = validate_tool_requests(args.directory, bundle)
    print(f"{args.example}: validated {count} Kubernetes manifests, intent and IAM migration. "
          f"Observed {rejections} Rego artifact rejections with witnesses and "
          f"{denied} denied and {allowed} allowed tool requests.")


if __name__ == "__main__":
    main()
