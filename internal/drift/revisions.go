package drift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"maps"
	"slices"

	"github.com/cuhawk/AegisMesh/internal/compiler"
)

// RevisionChange holds the values of a changed bundle section.
type RevisionChange struct {
	Path   string          `json:"path"`
	Action string          `json:"action"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

func readRevision(r io.Reader) (map[string]any, error) {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	var fields map[string]any
	if err := decoder.Decode(&fields); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("expected one compiled bundle object")
	}
	for _, field := range []string{"kubernetes", "ciliumHTTP", "spire"} {
		if _, ok := fields[field].([]any); !ok {
			return nil, fmt.Errorf("compiled bundle requires %s array", field)
		}
	}
	for _, field := range []string{"terraform", "iam"} {
		if _, ok := fields[field].(map[string]any); !ok {
			return nil, fmt.Errorf("compiled bundle requires %s object", field)
		}
	}
	return fields, nil
}

// CompareRevisions compares compiled artifacts offline. Object key order and
// JSON whitespace are immaterial. Array order is preserved.
func CompareRevisions(before, after io.Reader) ([]RevisionChange, error) {
	left, err := readRevision(before)
	if err != nil {
		return nil, fmt.Errorf("before revision: %w", err)
	}
	right, err := readRevision(after)
	if err != nil {
		return nil, fmt.Errorf("after revision: %w", err)
	}
	changes := make([]RevisionChange, 0)
	if err := compareSections("", left, right, &changes); err != nil {
		return nil, err
	}
	return changes, nil
}

func compareSections(prefix string, left, right map[string]any, changes *[]RevisionChange) error {
	keys := make(map[string]bool)
	for k := range left {
		keys[k] = true
	}
	for k := range right {
		keys[k] = true
	}
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		before, had := left[key]
		after, has := right[key]
		change := RevisionChange{Path: prefix + key, Action: "modified"}
		switch {
		case !had:
			change.Action = "added"
		case !has:
			change.Action = "removed"
		case key == "clusters" || prefix == "clusters/":
			a, aOK := before.(map[string]any)
			b, bOK := after.(map[string]any)
			if aOK && bOK {
				if err := compareSections(change.Path+"/", a, b, changes); err != nil {
					return err
				}
				continue
			}
		}
		if had {
			canonical, err := compiler.JSON(before)
			if err != nil {
				return err
			}
			change.Before = canonical
		}
		if has {
			canonical, err := compiler.JSON(after)
			if err != nil {
				return err
			}
			change.After = canonical
		}
		if !bytes.Equal(change.Before, change.After) {
			*changes = append(*changes, change)
		}
	}
	return nil
}

var revisionViewer = template.Must(template.New("revision-diff").Funcs(template.FuncMap{
	"value": func(raw json.RawMessage) string { return string(raw) },
}).Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisMesh policy diff</title>
<style>
body{font:1rem system-ui,sans-serif;margin:2rem auto;padding:0 1rem;max-width:100rem;color:#182230;background:#f7f8fb}
h2{font-size:1.15rem;overflow-wrap:anywhere}
section{margin:2rem 0}
.revisions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}
h3{margin:.25rem 0;font-size:1rem}
pre{padding:1rem;margin:0;overflow:auto;max-height:34rem;background:white;border:1px solid #aeb8c6;border-radius:4px;min-height:1.5rem}
</style></head>
<body><main><h1>Compiled policy diff</h1>
<p><a href="policy-diff.json">Download JSON</a></p>
{{range .}}<section>
<h2>{{.Path}} — {{.Action}}</h2>
<div class="revisions">
<div><h3>Before</h3><pre tabindex="0">{{if .Before}}{{value .Before}}{{else}}Absent{{end}}</pre></div>
<div><h3>After</h3><pre tabindex="0">{{if .After}}{{value .After}}{{else}}Absent{{end}}</pre></div>
</div></section>
{{else}}<p>No changes in the compiled policy.</p>{{end}}
</main></body></html>
`))

func RenderRevisionDiff(w io.Writer, changes []RevisionChange) error {
	return revisionViewer.Execute(w, changes)
}
