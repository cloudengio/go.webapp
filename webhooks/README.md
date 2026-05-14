# Package [cloudeng.io/webapp/webhooks](https://pkg.go.dev/cloudeng.io/webapp/webhooks?tab=doc)

```go
import cloudeng.io/webapp/webhooks
```


## Constants
### DefaultQueueSize, DefaultPayloadLimit
```go
DefaultQueueSize = 100
DefaultPayloadLimit = 1024 * 1024 // 1MB


```



## Variables
### ErrWrongServiceSpecificConfig
```go
ErrWrongServiceSpecificConfig = fmt.Errorf("missing service specific config")

```



## Functions
### Func NoopValidator
```go
func NoopValidator(req *http.Request) ([]byte, int)
```

### Func ParseSpecific
```go
func ParseSpecific[T any](c Config) (T, error)
```



## Types
### Type Config
```go
type Config struct {
	DeliveryPath   string            `yaml:"delivery_path" doc:"path to receive webhooks on"`
	RelayPath      string            `yaml:"relay_path" doc:"path to read relay payloads from"`
	Service        string            `yaml:"service" doc:"type of webhook to serve, e.g. github, etc."`
	MaxPayloadSize cmdyaml.ByteSize  `yaml:"max_payload_size" doc:"maximum allowed payload size for incoming webhook requests in bytes, e.g. 1048576 for 1MB"`
	MaxQueueSize   int               `yaml:"max_queue_size" doc:"maximum number of payloads to hold in the queue for processing, leave empty for default"`
	Specific       *cmdyaml.Deferred `yaml:",inline" doc:"additional details about the webhook specific to the type of webhook being served, leave empty for default"`
}
```
Config represents the configuration for a webhook server.

### Methods

```go
func (c Config) MarshalYAML() (interface{}, error)
```


```go
func (c Config) Options() []Option
```




### Type Option
```go
type Option func(*options)
```
Option is a function that configures the Relay.

### Functions

```go
func WithLogger(logger *slog.Logger) Option
```
WithLogger sets the logger for the Relay.


```go
func WithMaxPayloadSize(size int64) Option
```
WithMaxPayloadSize sets the maximum allowed payload size for incoming
webhook requests.


```go
func WithQueueSize(size int64) Option
```
WithQueueSize sets the size of the internal buffer for relaying payloads.
When the buffer is full the oldest payload is dropped.




### Type Relay
```go
type Relay struct {
	// contains filtered or unexported fields
}
```
Relay is an HTTP handler that receives JSON payloads and relays them
over a channel for subsequent processing. It is designed to be used in a
webhook server to receive webhook payloads and relay them to another http
handler that is used as a long polling endpoint for a client to receive the
payloads. The Webhook endpoint will accept POST requests with JSON payloads
and the Wait endpoint will accept GET requests and will block until a
payload is received. When the internal buffer is full the oldest webhook is
dropped to make room for the new one.

### Functions

```go
func NewRelay(ctx context.Context, validator Validator, opts ...Option) *Relay
```
NewRelay creates a new Relay with the provided Validator and options.
ctx governs the lifetime of the internal FIFO goroutine; cancel it or call
Stop to shut down cleanly.



### Methods

```go
func (r *Relay) DeliveryHandler() http.Handler
```
DeliveryHandler returns an http.Handler that serves the webhook endpoint for
receiving payloads.


```go
func (r *Relay) Handler(deliveryPath, relayPath string) func(w http.ResponseWriter, req *http.Request)
```
Handler returns an http.HandlerFunc that routes requests to the appropriate
handler based on the URL path. It expects the webhook endpoint to be at
deliveryPath and the wait endpoint to be at relayPath. Requests to other
paths will receive a 404 Not Found response.


```go
func (r *Relay) PollingHandler() http.Handler
```
PollingHandler returns an http.Handler that serves the wait endpoint for
long polling clients to receive payloads.


```go
func (r *Relay) ServeWebhook(w http.ResponseWriter, req *http.Request)
```
ServeWebhook handles incoming webhook requests, validates them using the
provided Validator, and relays the payload to the FIFO for processing.
If the internal buffer is full the oldest payload is dropped to make room.
It responds with appropriate HTTP status codes based on the validation
outcome.


```go
func (r *Relay) Stop(ctx context.Context)
```
Stop shuts down the internal FIFO goroutine. It blocks until the goroutine
exits or ctx is cancelled.


```go
func (r *Relay) WaitForWebhook(w http.ResponseWriter, req *http.Request)
```
WaitForWebhook waits for a payload to be received on the FIFO and responds
with the payload as JSON. It is intended to support long polling by blocking
until a webhook payload is available. If the request context is cancelled
while waiting, it logs the cancellation and returns without responding.




### Type SecretsConfig
```go
type SecretsConfig struct {
	User        string         `yaml:"user" doc:"user to associate with a key id if the KeySpec does not specify a user"`
	Secrets     []string       `yaml:"secrets" doc:"list of KeySpecs specifying the secrets to use for validating webhooks in cloudeng.io.cmdutil/keys.KeySpec format, i.e. id[user] or id. If not user is specified in the KeySpec, the user field will be used."`
	SecretSpecs []keys.KeySpec `yaml:"-" doc:"parsed KeySpecs from the Secrets field"`
}
```
SecretsConfig represents a common configuration that uses
cloudeng.io/cmdutil/keys.KeySpec to specify the secrets to be used for
validating webhooks. User and Secrets fields can be unmarshaled from YAML,
but the SecretSpecs field is populated based on those fields by the
UnmarshalYAML.

### Methods

```go
func (sc SecretsConfig) TokensFromContext(ctx context.Context) ([]keys.Token, error)
```


```go
func (sc *SecretsConfig) UnmarshalYAML(node *yaml.Node) error
```




### Type Validator
```go
type Validator func(r *http.Request) ([]byte, int)
```
Validator is called to validate and extract the webhook payload from an
incoming request. It should return the payload as a byte slice and an error
if validation fails.

### Functions

```go
func GitHubValidator(getTokens func(ctx context.Context) ([]keys.Token, error)) (Validator, error)
```
GitHubValidator returns a Validator that verifies GitHub webhook payloads
using one of possibly multiple Tokens returned by the getTokens function.
The token value is a byte slice that the validator uses to compute the HMAC
SHA256 signature of the payload and compare it to the signature provided in
the "X-Hub-Signature-256" header of the request. If a match is found, the
payload is considered valid and returned; if none of the returned tokens'
secrets match the signature, the payload is rejected and an appropriate HTTP
status code is returned to indicate the error. It is the responsibility of
the getTokens function to retrieve the tokens from the appropriate source,
such as a file or a key store.







