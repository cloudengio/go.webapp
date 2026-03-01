// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package cssutil provides utilities for working with CSS classes in HTML
// documents, including support for generating Tailwind CSS safelist
// configurations.
package cssutil

import (
	"io"
	"io/fs"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

// ParseHTMLClasses parses one or more HTML documents and returns a sorted,
// deduplicated slice of all CSS class names referenced in class attributes
// across all documents.
func ParseHTMLClasses(readers ...io.Reader) ([]string, error) {
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if attr.Key == "class" {
					for cls := range strings.FieldsSeq(attr.Val) {
						seen[cls] = true
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	for _, r := range readers {
		doc, err := html.Parse(r)
		if err != nil {
			return nil, err
		}
		walk(doc)
	}
	classes := make([]string, 0, len(seen))
	for cls := range seen {
		classes = append(classes, cls)
	}
	slices.Sort(classes)
	return classes, nil
}

// ParseHTMLClassesFS opens each name from fsys and calls ParseHTMLClasses
// with all of the resulting readers.
func ParseHTMLClassesFS(fsys fs.FS, names ...string) ([]string, error) {
	readers := make([]io.Reader, 0, len(names))
	closers := make([]io.Closer, 0, len(names))
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()
	for _, name := range names {
		f, err := fsys.Open(name)
		if err != nil {
			return nil, err
		}
		closers = append(closers, f)
		readers = append(readers, f)
	}
	return ParseHTMLClasses(readers...)
}

// TailwindSourceInline returns a Tailwind CSS v4 @source inline directive
// containing the provided class names. The directive instructs Tailwind
// to generate CSS for all listed classes regardless of whether they appear
// in scanned source files.
func TailwindSourceInline(classes []string) string {
	return `@source inline("` + strings.Join(classes, " ") + `");`
}
