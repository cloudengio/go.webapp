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
### DefaultForwardedHeaders
```go
DefaultForwardedHeaders = []string{
	"X-GitHub-Event",
	"X-GitHub-Delivery",
	"X-GitHub-Hook-ID",
}

```
DefaultForwardedHeaders are the request headers copied from an incoming
webhook delivery onto the long-poll response when WithForwardedHeaders is
not used. They carry the GitHub event type and delivery metadata a client
needs to dispatch events. The X-Hub-Signature-256 header is deliberately
omitted: the relay has already verified it, and the client has no secret to
re-check.

### ErrWrongServiceSpecificConfig
```go
ErrWrongServiceSpecificConfig = fmt.Errorf("missing service specific config")

```



## Functions
### Func GitHubWorkflowSessionKey
```go
func GitHubWorkflowSessionKey(header http.Header, body []byte) (string, bool)
```
GitHubWorkflowSessionKey is a SessionKeyFunc that groups the webhooks of a
GitHub workflow run: the workflow_run and workflow_job events of a run have
the same session, which is the run's id, and the workflow_run event with an
action of completed is the last. All other events are not part of a session.

### Func HashSessionPolicy
```go
func HashSessionPolicy(session string, n int) int
```
HashSessionPolicy is the default SessionPolicy: it hashes the session key.

### Func NoopValidator
```go
func NoopValidator(req *http.Request) ([]byte, int)
```

### Func ParseSpecific
```go
func ParseSpecific[T any](c Config) (T, error)
```

### Func SHA256SignatureFromHeader
```go
func SHA256SignatureFromHeader(headerName string) func(req *http.Request) ([]byte, int)
```
SHA256SignatureFromHeader returns a function that extracts and decodes the
HMAC SHA256 signature from the specified header in the HTTP request.

### Func SignHTTPRequest
```go
func SignHTTPRequest(header http.Header, payload []byte, secret []byte, headerName string) error
```
SignHTTPRequest signs the given payload using the provided secret and sets
the signature in the specified header of the HTTP request.



## Types
### Type Config
```go
type Config struct {
	DeliveryPath    string            `yaml:"delivery_path" doc:"path to receive webhooks on"`
	RelayPath       string            `yaml:"relay_path" doc:"path to read relay payloads from"`
	MaxPayloadSize  cmdyaml.ByteSize  `yaml:"max_payload_size" doc:"maximum allowed payload size for incoming webhook requests in bytes, e.g. 1048576 for 1MB"`
	MaxQueueSize    int               `yaml:"max_queue_size" doc:"maximum number of payloads to hold in the queue for processing, leave empty for default"`
	ExclusiveReads  bool              `yaml:"exclusive_reads" doc:"if true, at most one long poll reader is admitted at a time and concurrent readers are rejected with 409 Conflict"`
	Sessions        bool              `yaml:"sessions,omitempty" doc:"if true, webhooks that are part of the same session are relayed to the same long poll reader"`
	SessionTimeout  time.Duration     `yaml:"session_timeout,omitempty" doc:"if sessions are enabled, how long a session may go without a webhook before it is ended, leave empty for no timeout"`
	Service         string            `yaml:"service" doc:"type of webhook to serve, e.g. github-workflow, etc."`
	ServiceSpecific *cmdyaml.Deferred `yaml:"service_specific" doc:"additional details specific to the type of webhook being served, leave empty for default"`
}
```
Config represents the configuration for a webhook server.

### Methods

```go
func (c Config) MarshalYAML() (any, error)
```


```go
func (c Config) Options() []Option
```


```go
func (c *Config) UnmarshalYAML(node *yaml.Node) error
```


```go
func (c Config) Validate() error
```
Validate reports whether sessions are enabled for a service without them.




### Type Delivery
```go
type Delivery struct {
	// Headers are the forwarded headers, see WithForwardedHeaders.
	Headers http.Header    `json:"headers,omitzero"`
	Payload jsontext.Value `json:"payload"`
}
```
Delivery is a webhook as it is sent to a reader, one per line.


### Type Option
```go
type Option func(*options)
```
Option is a function that configures the Relay.

### Functions

```go
func WithCounters(deniedCounter, relayedCounter, readCounter webapp.CounterInc) Option
```
WithCounters sets the counters for the Relay. If any of the counters are
nil, they will be set to a no-op counter that does nothing when called.
deniedCounter is incremented when a request is denied because the payload
fails validation, e.g. due to an invalid signature. relayedCounter is
incremented when a payload is successfully relayed to the FIFO. readCounter
is incremented when a payload is successfully read from the FIFO and sent to
a client.


```go
func WithExclusiveReads(exclusive bool) Option
```
WithExclusiveReads configures the long-poll endpoint to admit at most one
reader at a time. While a reader is waiting for, or receiving, a delivery
any additional long-poll request is rejected immediately with 409 Conflict
rather than competing for deliveries. The default is to allow any number of
concurrent readers, with each delivery going to exactly one of them.


```go
func WithExpiry(ttl, scanInterval time.Duration) Option
```
WithExpiry configures the relay to drop queued deliveries that have
waited longer than ttl without being read by a client, guarding against
unbounded staleness when no client is polling. The queue is scanned every
scanInterval; if scanInterval is <= 0 it defaults to ttl. Expiry is disabled
(the default) when ttl is <= 0, in which case deliveries are only dropped by
the queue's drop-oldest behaviour when it is full.


```go
func WithForwardedHeaders(names ...string) Option
```
WithForwardedHeaders sets the request header names that are copied from
an incoming webhook delivery onto the long-poll response sent to clients.
It replaces DefaultForwardedHeaders; pass no names to forward none. Header
matching is case-insensitive and absent headers are skipped.


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


```go
func WithSessionPolicy(p SessionPolicy) Option
```
WithSessionPolicy sets the policy that binds sessions to readers, replacing
HashSessionPolicy. It has no effect without WithSessions.


```go
func WithSessionTimeout(timeout time.Duration) Option
```
WithSessionTimeout ends a session that has had no delivery for longer than
timeout, for sessions whose last delivery never arrives. A later delivery
for it starts a new session. Expiry is checked as deliveries arrive and
readers finish. A timeout <= 0, the default, disables it.


```go
func WithSessions(key SessionKeyFunc) Option
```
WithSessions keeps the deliveries of a session, as identified by key,
together. Readers must stream, see Relay.WaitForWebhook, and each gets its
own queue. A session is bound to a reader, chosen by the SessionPolicy, when
its first delivery arrives, and all of its deliveries go to that reader.
Deliveries that are not part of a session go to any reader. If no session
reader is waiting, the delivery waits for any reader.




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
outcome, and rejects, with 400, a payload that is not valid JSON.


```go
func (r *Relay) Stop(ctx context.Context)
```
Stop shuts down the internal FIFO goroutine. It blocks until the goroutine
exits or ctx is cancelled.


```go
func (r *Relay) WaitForWebhook(w http.ResponseWriter, req *http.Request)
```
WaitForWebhook responds to a long polling request with webhooks.
By default it waits for a webhook and responds with it as it was received:
the payload is the body and the forwarded headers are headers.
With the stream=1 query parameter it streams webhooks as they arrive,
each as a Delivery on a line of its own, until the request ends. If sessions
are enabled, see WithSessions, the request must stream, and is sent all of
the webhooks of the sessions bound to it, ending after the last of them,
as well as those that are not part of a session. Otherwise it is rejected
with 400 Bad Request. If the request context is cancelled while waiting,
it logs the cancellation and returns without responding. When exclusive
reads are configured (see WithExclusiveReads) and another reader is already
waiting, it responds immediately with 409 Conflict.




### Type SecretsConfig
```go
type SecretsConfig struct {
	Secrets     map[string][]string `yaml:"-" doc:"map of users to lists of secret IDs, where users are service specific (e.g. GitHub usernames or email addresses) and secret IDs identify entries in the key store"`
	SecretSpecs []keys.KeySpec      `yaml:"-" doc:"-"`
}
```
SecretsConfig represents the secrets used to validate incoming webhooks.
Keys are users (e.g. a GitHub username or email address) and values are
lists of secret IDs that identify entries in the key store. SecretSpecs is
populated automatically during unmarshal and must not be set directly.

YAML format (the node itself is the map — no wrapper key):

    alice@example.com:
      - secret-id-1
      - secret-id-2
    bob@example.com:
      - other-secret

Note that SecretsConfig cannot be inlined by a parent YAML struct, it must
always be a named field.

### Methods

```go
func (sc SecretsConfig) MarshalYAML() (any, error)
```


```go
func (sc SecretsConfig) TokensFromContext(ctx context.Context) ([]keys.Token, error)
```


```go
func (sc *SecretsConfig) UnmarshalYAML(node *yaml.Node) error
```




### Type SessionKeyFunc
```go
type SessionKeyFunc func(header http.Header, body []byte) (key string, last bool)
```
SessionKeyFunc identifies the session, if any, that a webhook delivery
belongs to. The only requirement is that it returns the same, non-empty
key for all deliveries of the same session and it returns true for the last
delivery of the session. Return an empty key indicates that the delivery
does not belong to any session. header is the header of the delivery
request and body its payload. The webhook delivery itself has already been
validated.


### Type SessionPolicy
```go
type SessionPolicy func(session string, n int) int
```
SessionPolicy chooses which of n > 0 session readers a new session is bound
to, returning an index in [0, n). It is called once per session, when its
first delivery arrives, and the session stays with that reader.


### Type Validator
```go
type Validator func(r *http.Request) ([]byte, int)
```
Validator is called to validate and extract the webhook payload from an
incoming request. It should return the payload as a byte slice and an error
if validation fails.

### Functions

```go
func SignatureValidator(getSignature func(req *http.Request) ([]byte, int), getTokens func(ctx context.Context) ([]keys.Token, error)) (Validator, error)
```
SignatureValidator returns a Validator that verifies webhook payloads
using one of possibly multiple Tokens returned by the getTokens function.
The token value is a byte slice that the validator uses to compute the
HMAC SHA256 signature of the payload and compare it to the signature
provided in the request header as returned by the getSignature function.
If a match is found, the payload is considered valid and returned; if none
of the returned tokens' secrets match the signature, the payload is rejected
and an appropriate HTTP status code is returned to indicate the error.
It is the responsibility of the getTokens function to retrieve the tokens
from the appropriate source, such as a file or a key store.







