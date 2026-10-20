// Copyright 2025 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package chromedputil

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// ListenHandler represents an event handler that subscribes to Chrome DevTools Protocol
// events when invoked with a context.
type ListenHandler func(ctx context.Context)

// Listen sets up listeners for Chrome DevTools Protocol events by calling each
// of the supplied handlers.
func Listen(ctx context.Context, handlers ...ListenHandler) {
	for _, handler := range handlers {
		handler(ctx)
	}
}

// NewListenHandler returns a handler for a specific CDP event that forwards
// received events to the provided channel.
func NewListenHandler[T any](ev cdp.Event[T], ch chan<- *T) ListenHandler {
	return func(ctx context.Context) {
		seq := chromedp.Events(ctx, ev)
		go func() {
			for event, err := range seq {
				if err != nil {
					return
				}
				e := event
				select {
				case ch <- &e:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// ConsoleArgsAsJSON converts the console API call arguments to a slice of marshalled
// JSON data, one per each argument to the original console.log call.
func ConsoleArgsAsJSON(ctx context.Context, event *runtime.EventConsoleAPICalled) ([][]byte, error) {
	values := make([][]byte, 0, len(event.Args))
	for _, arg := range event.Args {
		val, _, err := GetRemoteObjectValueJSON(ctx, arg)
		if err != nil {
			return nil, fmt.Errorf("failed to get remote object value: %+v %w", arg, err)
		}
		out, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON: %w", err)
		}
		values = append(values, out)
	}
	return values, nil
}

type loggingOptions struct {
	consoleCh         chan *runtime.EventConsoleAPICalled
	exceptionCh       chan *runtime.EventExceptionThrown
	networkResponseCh chan *network.EventResponseReceived
	networkRrequestCh chan *network.EventRequestWillBeSent
	eventCh           chan *log.EventEntryAdded
	anyCh             chan any
	handlers          []ListenHandler
}

// LoggingOption represents options to RunLoggingListener.
type LoggingOption func(*loggingOptions)

func handlerOption[T any](ev cdp.Event[T], handlers []ListenHandler) (chan *T, []ListenHandler) {
	ch := make(chan *T, 10)
	return ch, append(handlers, NewListenHandler(ev, ch))
}

func initCh[T any](ch chan T) chan T {
	if ch == nil {
		return make(chan T, 10)
	}
	return ch
}

// WithConsoleLogging enables logging of events of type 'runtime.EventConsoleAPICalled'.
func WithConsoleLogging() LoggingOption {
	return func(opts *loggingOptions) {
		opts.consoleCh, opts.handlers = handlerOption(runtime.ConsoleAPICalled, opts.handlers)
	}
}

// WithExceptionLogging enables logging of events of type 'runtime.EventExceptionThrown'.
func WithExceptionLogging() LoggingOption {
	return func(opts *loggingOptions) {
		opts.exceptionCh, opts.handlers = handlerOption(runtime.ExceptionThrown, opts.handlers)
	}
}

// WithEventEntryLogging enables logging of events of type 'log.EventEntryAdded'.
func WithEventEntryLogging() LoggingOption {
	return func(opts *loggingOptions) {
		opts.eventCh, opts.handlers = handlerOption(log.EntryAdded, opts.handlers)
	}
}

// WithNetworkLogging enables logging of events of type 'network.EventResponseReceived'
// and 'network.EventRequestWillBeSent'.
func WithNetworkLogging() LoggingOption {
	return func(opts *loggingOptions) {
		opts.networkResponseCh, opts.handlers = handlerOption(network.ResponseReceived, opts.handlers)
		opts.networkRrequestCh, opts.handlers = handlerOption(network.RequestWillBeSent, opts.handlers)
	}
}

// WithEventLogging enables logging for the specified CDP event.
func WithEventLogging[T any](ev cdp.Event[T]) LoggingOption {
	return func(opts *loggingOptions) {
		opts.anyCh = initCh(opts.anyCh)
		opts.handlers = append(opts.handlers, func(ctx context.Context) {
			seq := chromedp.Events(ctx, ev)
			go func() {
				for event, err := range seq {
					if err != nil {
						return
					}
					select {
					case opts.anyCh <- event:
					case <-ctx.Done():
						return
					}
				}
			}()
		})
	}
}

type jsonValue struct {
	Value jsontext.Value `json:"value"`
}

// RunLoggingListener starts the logging listener for Chrome DevTools Protocol events.
// It returns a channel that is closed when the goroutine that listens on events
// terminates.
func RunLoggingListener(ctx context.Context, logger *slog.Logger, opts ...LoggingOption) chan struct{} {
	var options loggingOptions
	for _, opt := range opts {
		opt(&options)
	}
	options.consoleCh = initCh(options.consoleCh)
	options.exceptionCh = initCh(options.exceptionCh)
	options.networkResponseCh = initCh(options.networkResponseCh)
	options.networkRrequestCh = initCh(options.networkRrequestCh)
	options.eventCh = initCh(options.eventCh)
	options.anyCh = initCh(options.anyCh)

	Listen(ctx, options.handlers...)

	doneCh := make(chan struct{})
	startCh := make(chan struct{})
	go func() {
		close(startCh)
		var wg sync.WaitGroup
		for {
			select {
			case event := <-options.consoleCh:
				// Run asynchronously since ConsoleArgsAsJSON will call back into
				// chromedp which may cause a deadlock depending on the overall
				// state of chromedp.
				wg.Go(func() {
					s, err := ConsoleArgsAsJSON(ctx, event)
					if err != nil {
						logger.Error("Failed to marshal console args to JSON", "error", err)
						return
					}
					attrs := []slog.Attr{}
					for i, arg := range s {
						var jv jsonValue
						if err := json.Unmarshal(arg, &jv); err != nil {
							attrs = append(attrs, slog.Attr{Key: fmt.Sprintf("%03d", i), Value: slog.StringValue(string(arg))})
						} else {
							attrs = append(attrs, slog.Attr{Key: fmt.Sprintf("%03d", i), Value: slog.AnyValue(jv.Value)})
						}
					}
					logger.LogAttrs(ctx, slog.LevelInfo, "Console API called", attrs...)
				})
			case event := <-options.exceptionCh:
				logger.Error("Exception thrown", slog.Any("event", event))
				logger.Error("Exception details",
					slog.Any("stackTrace", event.ExceptionDetails.StackTrace),
					slog.Any("exception", event.ExceptionDetails.Exception),
					slog.Any("lineNumber", event.ExceptionDetails.LineNumber),
					slog.Any("columnNumber", event.ExceptionDetails.ColumnNumber),
				)
			case event := <-options.eventCh:
				logger.Info("Log entry added", slog.Any("event", event.Entry))
			case event := <-options.anyCh:
				logger.Info("Other event", slog.Any("event", event))
			case response := <-options.networkResponseCh:
				logger.Info("Network response received", "url", response.Response.URL, "status", response.Response.Status)
			case request := <-options.networkRrequestCh:
				logger.Info("Network request received", "url", request.Request.URL, "method", request.Request.Method)
			case <-ctx.Done():
				wg.Wait()
				close(doneCh)
				return
			}
		}
	}()
	<-startCh
	return doneCh
}
