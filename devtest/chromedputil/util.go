// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// Package chromedputil provides utility functions for working with the
// Chrome DevTools Protocol via github.com/chromedp.
package chromedputil

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"text/template"

	"cloudeng.io/cicd"
	"cloudeng.io/logging/ctxlog"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

//go:embed javascript_functions.js
var javascriptFunctions string

// ListGlobalFunctions returns a list of all global function names defined in the
// current context.
func ListGlobalFunctions(ctx context.Context) ([]string, error) {
	return chromedp.Run(ctx,
		chromedp.Evaluate[[]string](`Object.getOwnPropertyNames(window).filter(
			key => typeof window[key] === 'function'
		);`))
}

// WaitForPromise waits for a promise to resolve in the given evaluate parameters.
func WaitForPromise(p *runtime.EvaluateParams) {
	chromedp.EvalAwaitPromise(p)
}

var loadTpl = template.Must(template.New("loadJS").Parse(`
(async () => {
  let r = await chromedp_utils.loadScript("{{.Script}}");
  console.log("Script load result:", r);
  return r;
})();`))

// SourceScript loads a JavaScript script into the current page.
func SourceScript(ctx context.Context, script string) error {
	type loadResult struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	scr := strings.Builder{}
	data := struct {
		Script string
	}{
		Script: script,
	}
	err := loadTpl.Execute(&scr, data)
	if err != nil {
		return fmt.Errorf("failed to execute load template: %w", err)
	}
	if err := chromedp.Do(ctx, chromedp.Evaluate[chromedp.Void](javascriptFunctions)); err != nil {
		return fmt.Errorf("failed to evaluate load script %s: %w", script, err)
	}
	result, err := chromedp.Run(ctx, chromedp.Evaluate[loadResult](scr.String(), WaitForPromise))
	if err != nil {
		return fmt.Errorf("failed to evaluate load script %s: %w", script, err)
	}
	if !result.Success {
		return fmt.Errorf("failed to load script: %s", result.Error)
	}
	return nil
}

// GetRemoteObjectRef retrieves a remote object's metadata, ie.
// type, object id etc (but not it's value).
func GetRemoteObjectRef(ctx context.Context, name string) (*runtime.RemoteObject, error) {
	ro, err := chromedp.Run(ctx, chromedp.Evaluate[*runtime.RemoteObject](name, func(p *runtime.EvaluateParams) {
		p.Silent = new(true)
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate %s: %w", name, err)
	}
	if ro == nil {
		return nil, fmt.Errorf("failed to get remote object: %s", name)
	}
	return ro, nil
}

func callon(ctx context.Context, fn string, objectID runtime.RemoteObjectID, deep bool) (*runtime.RemoteObject, error) {
	if objectID == "" {
		return nil, fmt.Errorf("missing objectID")
	}
	params := runtime.CallFunctionOnParams{
		FunctionDeclaration: fn,
		ObjectID:            objectID,
	}
	if deep {
		params.SerializationOptions = &runtime.SerializationOptions{
			Serialization: runtime.SerializationOptionsSerializationDeep,
		}
	} else {
		params.ReturnByValue = new(true)
	}
	res, err := chromedp.Call(ctx, runtime.CallFunctionOn, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call function %s on object %s: %w", fn, objectID, err)
	}
	if res.ExceptionDetails != nil {
		return nil, fmt.Errorf("javascript exception: %w", &chromedp.ExceptionError{ExceptionDetails: res.ExceptionDetails})
	}
	return res.Result, nil
}

// GetRemoteObjectValueJSON retrieves a remote object's (using ObjectID)
// value using JSON serialization. The object is looked up by its ID and hence
// the supplied ObjectID must be a reference to the object with the ObjectID
// field set. Objects which already contain a JSON value will return that value
// immediately.
// NOTE that GetRemoteObjectValueJSON will return an empty or incomplete serialization
// for platform objects, the ClassName will generally be indicative of whether
// the object is a platform object, e.g Response or Promise.
func GetRemoteObjectValueJSON(ctx context.Context, object *runtime.RemoteObject) (*runtime.RemoteObject, jsontext.Value, error) {
	if object.Value != nil {
		return object, object.Value, nil
	}
	if object.Type == "undefined" {
		object.Value = jsontext.Value(`"undefined"`)
		return object, object.Value, nil
	}
	return safeClone(ctx, object.ObjectID)
}

// IsPlatformObjectError checks if the error is due to a platform object serialization
// error. The only reliable way to determine if an object is a platform object in
// chrome is to attempt a deep serialization and check for this error.
func IsPlatformObjectError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "unknown DeepSerializedValueType value: platformobject")
}

// safeClone uses the javascript safeClone method to attempt to summarize/capture
// platform object details.
func safeClone(ctx context.Context, objectID runtime.RemoteObjectID) (*runtime.RemoteObject, jsontext.Value, error) {
	if err := chromedp.Do(ctx, chromedp.Evaluate[chromedp.Void](javascriptFunctions)); err != nil {
		return nil, nil, err
	}
	obj, err := callon(ctx, `function() { return chromedp_utils.safeClone(this); }`, objectID, false)
	if err != nil {
		return nil, nil, err
	}
	if obj.Type != "" && obj.ClassName != "" {
		return obj, obj.Value, nil
	}
	platformInfo := struct {
		Type      string `json:"_type,omitempty"`
		ClassName string `json:"className,omitempty"`
	}{}
	if err := json.Unmarshal(obj.Value, &platformInfo); err != nil {
		return obj, obj.Value, nil
	}
	if platformInfo.Type != "" {
		obj.ClassName = platformInfo.ClassName
	}
	return obj, obj.Value, nil
}

// IsPlatformObject returns true if the given remote object is a platform object.
// The obj argument must have been obtained via a call to GetRemoteObjectValueJSON.
func IsPlatformObject(obj *runtime.RemoteObject) bool {
	if obj == nil {
		return false
	}
	platformInfo := struct {
		Type string `json:"_type,omitempty"`
	}{}
	if err := json.Unmarshal(obj.Value, &platformInfo); err != nil {
		return false
	}
	return platformInfo.Type != ""
}

// CertPoolAllocatorOption returns an ExecAllocatorOption that configures Chrome
// to suppress certificate errors for connections whose certificate chain contains
// a certificate matching one of the provided CA certificates. It uses Chrome's
// --ignore-certificate-errors-spki-list flag with the SHA-256 SPKI fingerprint
// of each certificate. This is intended for testing against servers using locally
// issued certificates such as those from the Pebble ACME test server.
func CertPoolAllocatorOption(certs ...*x509.Certificate) chromedp.ExecAllocatorOption {
	hashes := make([]string, len(certs))
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		hashes = append(hashes, base64.StdEncoding.EncodeToString(sum[:]))
	}
	return chromedp.Flag("ignore-certificate-errors-spki-list", strings.Join(hashes, ","))
}

// WithExecAllocatorForCI returns a chromedp context with an ExecAllocator
// configured appropriately for CI systems as opposed to when running locally.
// The CI configuration may disable sandboxing for example.
func WithExecAllocatorForCI(ctx context.Context, userDataDir string, extraExecAllocOpts ...chromedp.ExecAllocatorOption) (context.Context, func()) {
	chromeBin := ChromeBinPathOnCI()
	modifyCmd := func(cmd *exec.Cmd) {
		ctxlog.Info(ctx, "chrome command line", "path", cmd.Path, "args", cmd.Args[1:])
	}
	if len(chromeBin) == 0 {
		opts := slices.Clone(chromedp.DefaultExecAllocatorOptions[:])
		opts = append(opts, extraExecAllocOpts...)
		opts = append(opts, chromedp.ModifyCmdFunc(modifyCmd))
		return chromedp.NewExecAllocator(ctx, opts...)
	}
	ctxlog.Info(ctx, "detected CI environment", "CHROME_BIN_PATH", chromeBin)
	if len(userDataDir) == 0 {
		userDataDir = UserDataDirOnCI()
	}
	ctxlog.Warn(ctx, "chromedp/chrome: sandboxing disabled")
	allOpts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(chromeBin),
	}
	if len(userDataDir) > 0 {
		ctxlog.Info(ctx, "detected CI environment", "CHROME_USER_DATA_DIR", userDataDir)
		allOpts = append(allOpts, chromedp.UserDataDir(userDataDir))
	}
	allOpts = append(allOpts, AllocatorOptsForCI...)
	allOpts = append(allOpts, extraExecAllocOpts...)
	allOpts = append(allOpts, chromedp.ModifyCmdFunc(modifyCmd))
	return chromedp.NewExecAllocator(ctx, allOpts...)
}

// UserDataDirOnCI returns the user data directory for Chrome on CI.
func UserDataDirOnCI() string {
	return os.Getenv("CHROME_USER_DATA_DIR")
}

// ChromeBinPathOnCI returns the Chrome binary path for CI.
func ChromeBinPathOnCI() string {
	return os.Getenv("CHROME_BIN_PATH")
}

// NativeMessagingHostsDir returns the machine/user-wide directory where
// Chrome looks for native messaging host manifests, keyed off the browser
// variant (stable, Chrome for Testing, Chromium, ...) inferred from
// ChromeBinPathOnCI. This is where a real, installed Chrome looks; a Chrome
// launched with a non-default --user-data-dir, as every ExecAllocator in
// this package does, also (and more reliably, since it needs no OS/variant
// guessing at all) looks in UserDataNativeMessagingHostsDir(userDataDir) —
// prefer that one for anything launched via this package, and use this
// function only when the manifest must be visible to Chrome regardless of
// which profile it's launched against.
func NativeMessagingHostsDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	switch goruntime.GOOS {
	case "darwin":
		return filepath.Join(configDir, darwinChromedpProduct(), "NativeMessagingHosts")
	case "linux":
		return filepath.Join(configDir, linuxChromedpProduct(), "NativeMessagingHosts")
	default:
		panic(fmt.Sprintf("unsupported OS: %s", goruntime.GOOS))
	}
}

// UserDataNativeMessagingHostsDir returns the directory where Chrome looks
// for native messaging host manifests scoped to a specific profile:
// Chromium resolves its DIR_USER_NATIVE_MESSAGING relative to DIR_USER_DATA
// (i.e. --user-data-dir) on every platform, so, unlike NativeMessagingHostsDir,
// this needs no per-OS or per-browser-variant guessing, and works the same
// way for every ExecAllocator this package creates (they all set
// --user-data-dir; see WithExecAllocatorForCI and UserDataDirOnCI). This is
// the directory to write a manifest to for any Chrome launched by this
// package, and is the only mechanism confirmed to work against a Chrome for
// Testing build's own profile directory, as opposed to the real,
// machine-wide location NativeMessagingHostsDir guesses at.
func UserDataNativeMessagingHostsDir(userDataDir string) string {
	return filepath.Join(userDataDir, "NativeMessagingHosts")
}

func darwinChromedpProduct() string {
	// Determine Chrome variant from the CI binary path, defaulting to
	// standard Google Chrome.
	product := "Google/Chrome"
	if bin := ChromeBinPathOnCI(); bin != "" {
		switch {
		case strings.Contains(bin, "for Testing"):
			// Chrome for Testing's Application Support directory is a
			// single "Google Chrome for Testing" component, unlike stable
			// Chrome's, which nests under "Google/Chrome".
			product = "Google Chrome for Testing"
		case strings.Contains(bin, "Chromium"):
			product = "Chromium"
		case strings.Contains(bin, "Canary"):
			product = "Google/Chrome Canary"
		}
	}
	return product
}

func linuxChromedpProduct() string {
	// Determine Chrome variant directory from the CI binary path,
	// defaulting to standard Google Chrome.
	product := "google-chrome"
	if bin := ChromeBinPathOnCI(); bin != "" {
		switch {
		case strings.Contains(bin, "chrome-for-testing"), strings.Contains(bin, "for Testing"):
			product = "google-chrome-for-testing"
		case strings.Contains(bin, "chromium"):
			product = "chromium"
		case strings.Contains(bin, "beta"):
			product = "google-chrome-beta"
		case strings.Contains(bin, "unstable"), strings.Contains(bin, "dev"), strings.Contains(bin, "canary"):
			product = "google-chrome-unstable"
		}
	}
	return product
}

// SkipTestsIfNoChromeForTesting skips the test if chrome-for-testing is not
// available on the system, currently this is only implemented for linux/arm64.
func SkipTestsIfNoChromeForTesting(t cicd.TestingTSkip) {
	cicd.SkipIf(t, "skipping tests if no chrome-for-testing available on CI",
		goruntime.GOOS == "linux" && goruntime.GOARCH == "arm64")
}

var (

	// AllocatorOptsForCI are the default ExecAllocator options for CI environments,
	// they extend chromedp.DefaultExecAllocatorOptions.
	AllocatorOptsForCI = []chromedp.ExecAllocatorOption{
		// Replicating chromedp.DefaultExecAllocatorOptions but
		// with modifications for CI environments and avoiding the possibility
		// of enable/disable features conflicts.

		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", "new"),

		chromedp.Flag("disable-background-networking", true),
		// don't use enable-features + disable-features in the same command line
		// since it's unclear which takes precedence.
		// chromedp.Flag("enable-features", "NetworkService,NetworkServiceInProcess"),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-features", "site-per-process,Translate,BlinkGenPropertyTrees"),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("enable-automation", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),

		// Additional flags for CI.
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-crash-reporter", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-features", "MetricsReporting,UserMetrics"),
	}
)

// AllocatorOptsVerboseLogging provides ExecAllocator options for verbose logging
// at the specified level.
func AllocatorLoggingWithLevel(level int) []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{
		chromedp.Flag("enable-logging", "stderr"),
		chromedp.Flag("v", fmt.Sprintf("%d", level)),
	}
}

// WithContextForCI returns a chromedp context that may be different on a CI
// system than when running locally. The CI configuration may disable
// sandboxing etc. The ExecAllocator is always created with appropriate options for
// the various CI environments and extraExecAllocOpts is appended to these.
func WithContextForCI(ctx context.Context, userDataDir string, extraExecAllocOpts []chromedp.ExecAllocatorOption, opts ...chromedp.ContextOption) (context.Context, func()) {
	ctx, cancelA := WithExecAllocatorForCI(ctx, userDataDir, extraExecAllocOpts...)
	ctx, cancelB := chromedp.NewContext(ctx, opts...)
	return ctx, func() {
		cancelB()
		cancelA()
	}
}

type chromeWriter struct{ io.Writer }

func (w chromeWriter) Write(p []byte) (n int, err error) {
	out := []byte("chrome(output): ")
	lp := len(out) // subtract length of prefix from the returned value
	out = append(out, p...)
	nw, err := w.Writer.Write(out)
	if nw > lp {
		n = nw - lp
	}
	return n, err
}

// DebuggingExecOpts provides ExecAllocator options for debugging output.
// Debugging output is preceded by "chrome(output): " to distinguish it from
// the test output.
func DebuggingExecOpts(level int, debug bool) []chromedp.ExecAllocatorOption {
	var extraExecOpts []chromedp.ExecAllocatorOption
	if debug {
		extraExecOpts = append(extraExecOpts, chromedp.CombinedOutput(&chromeWriter{os.Stderr}))
		extraExecOpts = append(extraExecOpts, AllocatorLoggingWithLevel(level)...)
	}
	return extraExecOpts
}

// DebuggingCtxOpts provides Context options for debugging output.
// Debugging output is preceded by "chrome(output): " to distinguish it from
// the test output.
func DebuggingCtxOpts(logf func(string, ...any), debug bool) []chromedp.ContextOption {
	var ctxOpts []chromedp.ContextOption
	if debug {
		ctxOpts = append(ctxOpts,
			chromedp.WithBrowserOption(
				chromedp.WithBrowserDebugf(logf),
				chromedp.WithBrowserLogf(logf),
				chromedp.WithBrowserErrorf(logf)),
			chromedp.WithLogf(logf),
			chromedp.WithDebugf(logf),
			chromedp.WithErrorf(logf))
	}
	return ctxOpts
}
