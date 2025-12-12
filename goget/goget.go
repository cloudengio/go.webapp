// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package goget

import (
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/stretchr/testify/assert/yaml"
)

var metaTemplate = template.Must(template.New("go-import").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta name="go-import" content="{{.ImportPath}} {{.VCS}} {{.RepoURL}}">
</head>
<body>
    <a href="{{.RepoURL}}">Redirecting to source repository...</a>
</body>
</html>`))

// Spec represents a go-get meta tag specification.
// Fromhttps://go.dev/ref/mod#serving-from-proxy
// "The tag’s content must contain the repository root path, the version control
// system, and the URL, separated by spaces. See Finding a repository for a module
// path for details.
type Spec struct {
	ImportPath string `yaml:"import"`
	VCS        string `yaml:"vcs"`
	RepoURL    string `yaml:"repo"`
}

// Handler implements an HTTP handler that serves go-get meta tags
// based on the supplied specifications.
type Handler struct {
	Specs []Spec
}

func (h *Handler) GoGetHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("go-get") == "1" {
			for _, config := range h.Specs {
				// Check if the requested URL path matches the vanity import path
				if strings.HasPrefix(r.Host+r.URL.Path, config.ImportPath) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					err := metaTemplate.Execute(w, config)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// NewHandlerFromFS creates a new Handler instance by loading
// specifications from the specified file path within the provided fs.ReadFileFS.
// The file should contain a list YAML-formatted specifications as follows:
//
//   - import: "example.com/my/module"
//     vcs: "git"
//     repo: "github.com/user/repo"
func NewHandlerFromFS(fsys fs.ReadFileFS, path string) (*Handler, error) {
	specs, err := fsys.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var parsedSpecs []Spec
	err = yaml.Unmarshal(specs, &parsedSpecs)
	if err != nil {
		return nil, err
	}
	return &Handler{
		Specs: parsedSpecs,
	}, nil
}
