// aegismesh compiles, proves, and checks drift for a declarative intent.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/compiler"
	"github.com/cuhawk/AegisMesh/internal/drift"
	"github.com/cuhawk/AegisMesh/internal/intent"
	"github.com/cuhawk/AegisMesh/internal/prover"
	"github.com/pmezard/go-difflib/difflib"
	"go.yaml.in/yaml/v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || (args[0] != "compile" && args[0] != "prove" && args[0] != "drift") {
		return errors.New("usage: aegismesh {compile|prove|drift} -intent FILE [-out DIR] [-live FILE]")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	input := flags.String("intent", "", "intent JSON")
	out := flags.String("out", "", "new artifact directory")
	profile := flags.String("profile", "istio", "drift profile: istio or cilium-http")
	previous := flags.String("previous-tf", "", "previous Terraform JSON for an offline migration diff")
	live := flags.String("live", "", "exported Kubernetes List JSON")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" {
		return errors.New("supply an intent file with -intent")
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	in, err := intent.Decode(f)
	if err != nil {
		return err
	}
	switch args[0] {
	case "prove":
		if err := prover.RequireSafe(in); err != nil {
			return err
		}
		fmt.Println("All modeled invariants hold.")
		return nil
	case "compile":
		if *out == "" {
			return errors.New("compile requires -out")
		}
	}
	bundle, err := compiler.Compile(in)
	if err != nil {
		return err
	}
	if args[0] == "compile" {
		return writeBundle(*out, *previous, bundle)
	}
	if *live == "" {
		return errors.New("drift requires -live")
	}
	data, err := os.ReadFile(*live)
	if err != nil {
		return err
	}
	var inventory struct {
		Kind  string           `json:"kind"`
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		return err
	}
	if inventory.Kind != "List" || inventory.Items == nil {
		return errors.New("live inventory must be a Kubernetes List with an items array")
	}
	switch *profile {
	case "istio":
	case "cilium-http":
		bundle.Kubernetes = bundle.CiliumHTTP
	default:
		return fmt.Errorf("unknown profile %q", *profile)
	}
	changes, err := drift.Compare(bundle, inventory.Items)
	if err != nil {
		return err
	}
	printed, err := compiler.JSON(changes)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(printed); err != nil {
		return err
	}
	if len(changes) != 0 {
		return errors.New("policy drift detected")
	}
	return nil
}

func writeBundle(out, previous string, b compiler.Bundle) error {
	out = filepath.Clean(out)
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("output already exists: %s", out)
	} else if !os.IsNotExist(err) {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(out), ".aegismesh-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for filename, objects := range map[string][]map[string]any{"kubernetes.yaml": b.Kubernetes, "cilium-http.yaml": b.CiliumHTTP} {
		var manifest strings.Builder
		for _, o := range objects {
			data, err := yaml.Marshal(o)
			if err != nil {
				return err
			}
			manifest.WriteString("---\n")
			manifest.Write(data)
		}
		if err := os.WriteFile(filepath.Join(dir, filename), []byte(manifest.String()), 0644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "gate.rego"), []byte(compiler.Gate), 0644); err != nil {
		return err
	}
	if previous != "" {
		delta, err := migrationDiff(previous, b.Terraform)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "iam.tf.json.diff"), []byte(delta), 0644); err != nil {
			return err
		}
	}
	artifacts := map[string]any{
		"bundle.json":        b,
		"iam.tf.json":        b.Terraform,
		"spire-entries.json": map[string]any{"entries": b.SPIRE},
	}
	if len(b.ToolAuthorizations) != 0 {
		artifacts["tool-authorization-data.json"] = map[string]any{"aegismesh_tool_authorizations": b.ToolAuthorizations}
	}
	for name, policy := range b.IAM {
		artifacts["iam-"+name+".json"] = policy
	}
	names := make([]string, 0, len(artifacts))
	for name := range artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := compiler.JSON(artifacts[name])
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			return err
		}
	}
	return os.Rename(dir, out)
}

func migrationDiff(previous string, desired map[string]any) (string, error) {
	data, err := os.ReadFile(previous)
	if err != nil {
		return "", err
	}
	var baseline map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&baseline); err != nil || baseline == nil || !json.Valid(data) {
		return "", errors.New("previous Terraform must be a single JSON object")
	}
	before, err := compiler.JSON(baseline)
	if err != nil {
		return "", err
	}
	after, err := compiler.JSON(desired)
	if err != nil {
		return "", err
	}
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(string(before)), B: difflib.SplitLines(string(after)),
		FromFile: "previous/iam.tf.json", ToFile: "desired/iam.tf.json", Context: 3,
	})
}
