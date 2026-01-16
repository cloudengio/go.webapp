// Copyright 2020 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webassets

import (
	"io/fs"
	"log/slog"
	"os"
	"time"

	"cloudeng.io/io/reloadfs"
)

// AssetsFlags represents the flags used to control loading of
// assets from the local filesystem to override those original embedded in
// the application binary.
type AssetsFlags struct {
	ReloadEnable    bool   `subcmd:"reload-enable,false,'if set, newer local filesystem versions of embedded asset files will be used'"`
	ReloadNew       bool   `subcmd:"reload-new-files,true,'if set, files that only exist on the local filesystem may be used'"`
	ReloadRoot      string `subcmd:"reload-root,$PWD,'the filesystem location that contains assets to be used in preference to embedded ones. This is generally set to the directory that the application was built in to allow for updated versions of the original embedded assets to be used. It defaults to the current directory. For external/production use this will generally refer to a different directory.'"`
	ReloadLogging   bool   `subcmd:"reload-logging,false,set to enable logging"`
	ReloadDebugging bool   `subcmd:"reload-debugging,false,set to enable debug logging"`
}

// OptionsFromFlags parses AssetsFlags to determine the options to be passed to
// NewAssets()
func OptionsFromFlags(rf *AssetsFlags) []AssetsOption {
	return rf.Config().Options()
}

// Config represents the configuration used to control loading of
// assets from the local filesystem to override those original embedded in
// the application binary.
type Config struct {
	ReloadEnable bool   `yaml:"reload_enable" doc:"if set, newer local filesystem versions of embedded asset files will be used"`
	ReloadNew    bool   `yaml:"reload_new" doc:"if set, files that only exist on the local filesystem may be used"`
	ReloadRoot   string `yaml:"reload_root" doc:"the filesystem location that contains assets to be used in preference to embedded ones. This is generally set to the directory that the application was built in to allow for updated versions of the original embedded assets to be used."`
}

// Config converts AssetsFlags to Config.
func (f AssetsFlags) Config() Config {
	return Config{
		ReloadEnable: f.ReloadEnable,
		ReloadNew:    f.ReloadNew,
		ReloadRoot:   f.ReloadRoot,
	}
}

// Options converts Config to AssetsOption. If ReloadRoot is empty
// it defaults to the current directory, if not empty, os.ExpandEnv is
// called to expand environment variables.
func (c Config) Options() []AssetsOption {
	if !c.ReloadEnable {
		return nil
	}
	var opts []AssetsOption
	root := c.ReloadRoot
	if len(root) == 0 {
		root, _ = os.Getwd()
	} else {
		root = os.ExpandEnv(root)
	}
	opts = append(opts, WithReloading(root, time.Now(), c.ReloadNew))
	return opts
}

type assets struct {
	fs.FS
	logger      *slog.Logger
	reloadAfter time.Time
	reloadFrom  string
	loadNew     bool
}

// AssetsOption represents an option to NewAssets.
type AssetsOption func(a *assets)

// WithReloading enables reloading of assets from the specified
// location if they have changed since 'after'; loadNew controls whether
// new files, ie. those that exist only in location, are loaded as opposed.
// See cloudeng.io/io/reloadfs.
func WithReloading(location string, after time.Time, loadNew bool) AssetsOption {
	return func(a *assets) {
		a.reloadFrom = location
		a.reloadAfter = after
		a.loadNew = loadNew
	}
}

func WithLogger(logger *slog.Logger) AssetsOption {
	return func(a *assets) {
		a.logger = logger
	}
}

// NewAssets returns an fs.FS that is configured to be optional reloaded
// from the local filesystem or to be served directly from the supplied
// fs.FS. The EnableReloading option is used to enable reloading.
// Prefix is prepended to all names passed to the supplied fs.FS, which
// is typically obtained via go:embed. See RelativeFS for more details.
func NewAssets(prefix string, fsys fs.FS, opts ...AssetsOption) fs.FS {
	a := &assets{}
	for _, fn := range opts {
		fn(a)
	}
	if a.logger == nil {
		a.logger = slog.New(slog.DiscardHandler)
	}
	if len(a.reloadFrom) == 0 {
		rfs := relativeFS(prefix, fsys, a.logger)
		a.FS = rfs
		return a
	}
	a.logger = a.logger.With("pkg", "webapp/webassets")
	a.FS = reloadfs.New(a.reloadFrom,
		prefix,
		fsys,
		reloadfs.WithLogger(a.logger),
		reloadfs.WithReloadAfter(a.reloadAfter),
		reloadfs.WithNewFiles(a.loadNew),
	)
	return a
}
