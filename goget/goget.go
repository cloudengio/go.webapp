// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package goget

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"cloudeng.io/logging/ctxlog"
	"gopkg.in/yaml.v3"
)

var metaTemplate = template.Must(template.New("go-import").Parse(`
<html>
<head>
    <meta name="go-import" content="{{.ImportPath}} {{.VCS}} {{.RepoURL}}{{if .SubDirectory}} {{.SubDirectory}}{{end}}">
</head></html>`))

// Spec represents a go-get meta tag specification.
// From https://go.dev/ref/mod#serving-from-proxy
// "The tag’s content must contain the repository root path, the version control
// system, and the URL, separated by spaces. See Finding a repository for a module
// path for details.
type Spec struct {
	ImportPath          string `yaml:"import" cmd:"import path"`
	VCS                 string `yaml:"vcs" cmd:"version control system, e.g. git, hg, svn, bzr"`
	RepoURL             string `yaml:"repo" cmd:"repository URL"`
	SubDirectory        string `yaml:"subdir,omitempty" cmd:"subdirectory within the repository"` // optional subdirectory within the repository supported by go 1.25 and later
	importPathWithSlash string
}

func (s Spec) String() string {
	return fmt.Sprintf("%s %s %s", s.ImportPath, s.VCS, s.RepoURL)
}

// Handler implements an HTTP handler that serves go-get meta tags
// based on the supplied specifications.
type Handler struct {
	specs []Spec
}

// GoGetHandler returns an http.Handler that serves go-get meta tags
// for requests that include the "go-get=1" query parameter and match
// one of the defined specifications. If the query parameter is not present,
// the request is passed to the next handler. A 404 is returned if no
// specification matches.
func (h *Handler) GoGetHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("go-get") != "1" {
			next.ServeHTTP(w, r)
			return
		}
		importPath := r.Host + r.URL.Path
		for _, config := range h.specs {
			if importPath == config.ImportPath || strings.HasPrefix(importPath, config.importPathWithSlash) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				err := metaTemplate.Execute(w, config)
				if err != nil {
					ctxlog.Error(r.Context(),
						"failed to execute template",
						"request", r.URL.String(),
						"error", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}
		}
		http.NotFound(w, r)
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
	return NewHandler(parsedSpecs)
}

// NewHandler creates a new Handler instance for the provided
// specifications.
func NewHandler(specs []Spec) (*Handler, error) {
	for i := range specs {
		ns, err := specs[i].validate()
		if err != nil {
			return nil, err
		}
		specs[i] = ns
	}
	// Sort specs by import path length in descending order to ensure
	// that the longest prefix is matched first.
	slices.SortFunc(specs, func(a, b Spec) int {
		return len(b.ImportPath) - len(a.ImportPath)
	})
	return &Handler{
		specs: specs,
	}, nil
}

func (s Spec) validate() (Spec, error) {
	u, err := url.Parse(s.RepoURL)
	if err != nil {
		return s, fmt.Errorf("%s: invalid repo URL: %w", s, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "ssh" && u.Scheme != "git" {
		return s, fmt.Errorf("%s: invalid scheme for repo URL %s", s, u.Scheme)
	}
	if len(u.Host) == 0 {
		return s, fmt.Errorf("%s: no host in repo URL", s)
	}
	if len(u.Query()) != 0 {
		return s, fmt.Errorf("%s: repo URL must not contain query parameters", s)
	}
	switch s.VCS {
	case "":
		s.VCS = "git"
	case "git", "hg", "svn", "bzr":
	default:
		return s, fmt.Errorf("%s: unsupported VCS %q", s, s.VCS)
	}

	hasSlash := strings.HasSuffix(s.ImportPath, "/")
	if !hasSlash {
		s.importPathWithSlash = s.ImportPath + "/"
	} else {
		s.importPathWithSlash = s.ImportPath
		s.ImportPath = strings.TrimSuffix(s.ImportPath, "/")
	}
	return s, nil
}
