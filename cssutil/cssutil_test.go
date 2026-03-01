// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package cssutil_test

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"cloudeng.io/webapp/cssutil"
)

const testHTML = `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
  <div class="container mx-auto px-4">
    <h1 class="text-3xl font-bold text-gray-900">Hello</h1>
    <p class="text-sm text-gray-600 mt-2">World</p>
    <button class="bg-blue-500 text-white px-4 py-2 rounded">Click</button>
    <span class="text-sm text-gray-600">duplicate classes</span>
    <div class="container">nested duplicate</div>
  </div>
</body>
</html>`

func TestParseHTMLClasses(t *testing.T) {
	classes, err := cssutil.ParseHTMLClasses(strings.NewReader(testHTML))
	if err != nil {
		t.Fatalf("ParseHTMLClasses: %v", err)
	}

	want := []string{
		"bg-blue-500",
		"container",
		"font-bold",
		"mt-2",
		"mx-auto",
		"px-4",
		"py-2",
		"rounded",
		"text-3xl",
		"text-gray-600",
		"text-gray-900",
		"text-sm",
		"text-white",
	}

	if len(classes) != len(want) {
		t.Fatalf("got %d classes, want %d: %v", len(classes), len(want), classes)
	}
	for i, cls := range classes {
		if cls != want[i] {
			t.Errorf("classes[%d] = %q, want %q", i, cls, want[i])
		}
	}
}

const testHTML2 = `<!DOCTYPE html>
<html>
<body>
  <nav class="flex items-center gap-4">
    <a class="text-blue-600 hover:underline font-bold">Link</a>
  </nav>
</body>
</html>`

func TestParseHTMLClassesMultiple(t *testing.T) {
	classes, err := cssutil.ParseHTMLClasses(
		strings.NewReader(testHTML),
		strings.NewReader(testHTML2),
	)
	if err != nil {
		t.Fatalf("ParseHTMLClasses: %v", err)
	}

	want := []string{
		"bg-blue-500",
		"container",
		"flex",
		"font-bold",
		"gap-4",
		"hover:underline",
		"items-center",
		"mt-2",
		"mx-auto",
		"px-4",
		"py-2",
		"rounded",
		"text-3xl",
		"text-blue-600",
		"text-gray-600",
		"text-gray-900",
		"text-sm",
		"text-white",
	}

	if len(classes) != len(want) {
		t.Fatalf("got %d classes %v, want %d: %v", len(classes), classes, len(want), want)
	}
	for i, cls := range classes {
		if cls != want[i] {
			t.Errorf("classes[%d] = %q, want %q", i, cls, want[i])
		}
	}
}

func TestParseHTMLClassesDeeplyNested(t *testing.T) {
	// Build HTML with 513 nested divs, each with a unique class, to
	// guard against stack overflows in the iterative traversal.
	// golang.org/x/net/html caps the open element stack at 512 nodes.
	const depth = 513
	var b strings.Builder
	b.WriteString("<html><body>")
	for i := range depth {
		fmt.Fprintf(&b, `<div class="depth-%d">`, i)
	}
	for range depth {
		b.WriteString("</div>")
	}
	b.WriteString("</body></html>")

	classes, err := cssutil.ParseHTMLClasses(strings.NewReader(b.String()))
	if err == nil {
		t.Fatal("ParseHTMLClasses: expected error, got nil")
	}
	if len(classes) != 0 {
		t.Fatalf("got %d classes, want %d", len(classes), 0)
	}
}

func TestParseHTMLClassesEmpty(t *testing.T) {
	classes, err := cssutil.ParseHTMLClasses(strings.NewReader(`<html><body></body></html>`))
	if err != nil {
		t.Fatalf("ParseHTMLClasses: %v", err)
	}
	if len(classes) != 0 {
		t.Errorf("got %v, want empty", classes)
	}
}

func TestParseHTMLClassesFS(t *testing.T) {
	fsys := fstest.MapFS{
		"a.html": &fstest.MapFile{Data: []byte(testHTML)},
		"b.html": &fstest.MapFile{Data: []byte(testHTML2)},
	}
	classes, err := cssutil.ParseHTMLClassesFS(fsys, "a.html", "b.html")
	if err != nil {
		t.Fatalf("ParseHTMLClassesFS: %v", err)
	}
	want := []string{
		"bg-blue-500",
		"container",
		"flex",
		"font-bold",
		"gap-4",
		"hover:underline",
		"items-center",
		"mt-2",
		"mx-auto",
		"px-4",
		"py-2",
		"rounded",
		"text-3xl",
		"text-blue-600",
		"text-gray-600",
		"text-gray-900",
		"text-sm",
		"text-white",
	}
	if len(classes) != len(want) {
		t.Fatalf("got %d classes %v, want %d: %v", len(classes), classes, len(want), want)
	}
	for i, cls := range classes {
		if cls != want[i] {
			t.Errorf("classes[%d] = %q, want %q", i, cls, want[i])
		}
	}
}

func TestTailwindSourceInline(t *testing.T) {
	classes := []string{"bg-blue-500", "font-bold", "text-white"}
	got := cssutil.TailwindSourceInline(classes)
	want := `@source inline("bg-blue-500 font-bold text-white");`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTailwindSourceInlineInjection(t *testing.T) {
	// Class names containing '"' or ')' must be dropped to prevent injection
	// out of the @source inline("...") directive.
	classes := []string{
		"safe-class",
		`"); @import "malicious.css"; //`,
		`hover:focus)`,
		"another-safe",
	}
	got := cssutil.TailwindSourceInline(classes)
	want := `@source inline("safe-class another-safe");`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTailwindSourceInlineEmpty(t *testing.T) {
	got := cssutil.TailwindSourceInline(nil)
	want := `@source inline("");`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
