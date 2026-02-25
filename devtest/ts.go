// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package devtest

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"time"
)

// TypescriptOption represents an option to NewTypescriptSources.
type TypescriptOption func(o *typescriptOptions)

type typescriptOptions struct {
	compiler string
	target   string
}

// WithTypescriptCompiler sets the TypeScript compiler to use.
// The default is "tsc".
func WithTypescriptCompiler(compiler string) TypescriptOption {
	return func(o *typescriptOptions) {
		o.compiler = compiler
	}
}

// WithTypescriptTarget sets the target version for the TypeScript compiler.
// The default is "es2015".
func WithTypescriptTarget(target string) TypescriptOption {
	return func(o *typescriptOptions) {
		o.target = target
	}
}

// TypescriptSources represents a collection of TypeScript source files that
// can be compiled using the TypeScript compiler.
type TypescriptSources struct {
	options typescriptOptions
	dir     string
	fs      fs.StatFS
	files   []string
	last    time.Time
}

// NewTypescriptSources creates a new instance of TypescriptSources
func NewTypescriptSources(opts ...TypescriptOption) *TypescriptSources {
	tsc := &TypescriptSources{}
	for _, fn := range opts {
		fn(&tsc.options)
	}
	if tsc.options.target == "" {
		tsc.options.target = "es2015"
	}
	if tsc.options.compiler == "" {
		tsc.options.compiler = "tsc"
	}
	return tsc
}

// SetFiles sets the directory and files for the TypeScript sources.
// The output will be in the same directory, 'dir',
// as the input files.
func (ts *TypescriptSources) SetDirAndFiles(dir string, files ...string) {
	ts.dir = dir
	ts.fs = os.DirFS(dir).(fs.StatFS)
	ts.files = append([]string(nil), files...)
}

// Compile compiles the TypeScript sources that have been modified
// since it was last run.
func (ts *TypescriptSources) Compile(ctx context.Context) error {
	if ts.fs == nil {
		return fmt.Errorf("no fs set (call SetDirAndFiles first)")
	}
	if len(ts.files) == 0 {
		return fmt.Errorf("no TypeScript files configured")
	}
	modified := []string{}
	for _, candidate := range ts.files {
		fi, err := ts.fs.Stat(candidate)
		if err != nil {
			return err
		}
		if fi.ModTime().After(ts.last) {
			modified = append(modified, candidate)
		}
	}
	if len(modified) == 0 {
		return nil // nothing to compile
	}
	compilerPath, err := exec.LookPath(ts.options.compiler)
	if err != nil {
		return fmt.Errorf("failed to find typescript compiler %q in PATH: %w", ts.options.compiler, err)
	}

	args := []string{"--target", ts.options.target}
	args = append(args, modified...)
	// TODO: validate compiler name and arguments to ensure they are valid.
	cmd := exec.CommandContext(ctx, compilerPath, args...) //nolint:gosec // G702
	cmd.Dir = ts.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to compile TypeScript: %v: %v: output: %s", err, cmd.Args, out)
	}
	ts.last = time.Now()
	return nil
}
