"""Validate the example against pinned upstream schemas and the emitted gate."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
from urllib.request import urlopen

import jsonschema
import yaml

CILIUM = "https://raw.githubusercontent.com/cilium/cilium/v1.18.5/pkg/k8s/apis/cilium.io/client/crds/v2/"
ISTIO = "https://raw.githubusercontent.com/istio/istio/1.27.8/manifests/charts/base/files/crd-all.gen.yaml"
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
    for number, mutate in enumerate([
        lambda b: b["kubernetes"][0]["spec"]["egressDeny"][0]["toCIDR"].remove("169.254.169.254/32"),
        lambda b: b["iam"]["reader-role-access"]["Statement"][0].update(Action=["s3:*"]),
        lambda b: b["iam"]["reader-role-access"]["Statement"][0].update(Resource=["*"]),
        lambda b: b["iam"]["reader-role-trust"]["Statement"][0].pop("Condition"),
        lambda b: b["spire"][0].update(x509_svid_ttl=3601),
        lambda b: b["terraform"]["resource"]["aws_iam_role_policy"]["reader_role"].update(policy="{}"),
        lambda b: b["ciliumHTTP"][0]["spec"]["egressDeny"][0]["toCIDR"].remove("fd00:ec2::254/128"),
        lambda b: next(x for x in b["kubernetes"] if x["kind"] == "PeerAuthentication")["spec"].update(mtls={"mode": "PERMISSIVE"}),
        lambda b: next(x for x in b["kubernetes"] if x["kind"] == "AuthorizationPolicy")["spec"].update(rules=[{}]),
    ], 1):
        altered = copy.deepcopy(original)
        mutate(altered)
        evaluate(altered, "false", number)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    schema = json.loads((root / "schemas/intent.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(json.loads((root / "examples/multitenant.json").read_text()), schema)

    schemas = dict(crd_schemas(CILIUM + "ciliumnetworkpolicies.yaml"))
    schemas.update(crd_schemas(CILIUM + "ciliumclusterwidenetworkpolicies.yaml"))
    schemas.update(crd_schemas(ISTIO))
    schemas["v1", "ServiceAccount"] = json.loads(fetch(KUBERNETES + "serviceaccount-v1.json"))
    bundle = json.loads((args.directory / "bundle.json").read_text())
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
    validate_gate(args.directory, bundle)
    print(f"Validated {count} Kubernetes manifests, example intent, IAM migration and 9 Rego rejections.")


if __name__ == "__main__":
    main()
