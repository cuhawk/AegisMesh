package drift

import (
	"strings"
	"testing"
)

func TestCompareRevisions(t *testing.T) {
	const before = `{"kubernetes":[],"ciliumHTTP":[],"spire":[],"terraform":{"b":2,"a":1},"iam":{},"obsolete":null}`
	const after = `{"spire":[],"ciliumHTTP":[],"kubernetes":[],"terraform":{"a":1,"b":2},"iam":{"doc":"<script>alert(1)</script>"},"tetragon":[]}`
	changes, err := CompareRevisions(strings.NewReader(before), strings.NewReader(after))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 || changes[0].Path != "iam" || changes[0].Action != "modified" ||
		changes[1].Path != "obsolete" || changes[1].Action != "removed" || strings.TrimSpace(string(changes[1].Before)) != "null" ||
		changes[2].Path != "tetragon" || changes[2].Action != "added" || changes[2].Before != nil {
		t.Fatalf("unexpected revision changes: %+v", changes)
	}
	var page strings.Builder
	if err := RenderRevisionDiff(&page, changes); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page.String(), "<script>") || !strings.Contains(page.String(), "alert(1)") {
		t.Fatal("viewer did not escape and display revision content")
	}

	changes, err = CompareRevisions(strings.NewReader(after), strings.NewReader(" "+after+"\n"))
	if err != nil || len(changes) != 0 {
		t.Fatalf("equal revisions produced %v, %v", changes, err)
	}
	for _, invalid := range []string{`{}`, `null`, after + `{}`, after + `!`} {
		if _, err := CompareRevisions(strings.NewReader(before), strings.NewReader(invalid)); err == nil {
			t.Fatalf("accepted malformed revision %q", invalid)
		}
	}
}
