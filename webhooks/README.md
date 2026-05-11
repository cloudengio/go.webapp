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



## Types
### Type Config
```go
type Config struct {
	PublicAddr   string            `yaml:"public_addr" doc:"public address to serve webhooks on"`
	PublicIPACL  ipacl.Config      `yaml:"public_ip_acl" doc:"ACL of IPs allowed to access the webhook, if not specified all IPs are allowed"`
	PrivateAddr  string            `yaml:"private_addr" doc:"private address to listen on for webhook requests"`
	PrivateIPACL ipacl.Config      `yaml:"private_ip_acl" doc:"ACL of IPs allowed to access the webhook on the private address, if not specified all IPs are allowed"`
	Path         string            `yaml:"path" doc:"path to serve webhooks on"`
	Service      string            `yaml:"service" doc:"type of webhook to serve, e.g. github, etc."`
	Specific     *cmdyaml.Deferred `yaml:",inline" doc:"additional details about the webhook specific to the type of webhook being served"`
}
```
Config represents the configuration for a webhook server.

### Methods

```go
func (c Config) Github() (*GithubWebhookConfig, error)
```




### Type GithubWebhookConfig
```go
type GithubWebhookConfig struct {
	KeychainItemUser    string `yaml:"secret_user" doc:"user name of the key containing the GitHub webhook secret"`
	KeychainItemTokenID string `yaml:"secret_id" doc:"ID of the key containing the GitHub webhook secret as a token"`
}
```
GithubWebhookConfig represents the configuration specific to a GitHub
webhook. In particular the secrete used to validate the webhook requests
is accessed via a cloudeng.io/cmdutil/keys.InMemoryKeyStore item specified
by the KeychainItemUser and KeychainItemTokenID fields. The keystore itself
will be populated by the server hosting the webhook.


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
func WithMaxPayloadSize(size int) Option
```
WithMaxPayloadSize sets the maximum allowed payload size for incoming
webhook requests.


```go
func WithQueueSize(size int) Option
```
WithQueueSize sets the size of the channel buffer for relaying payloads.




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
payload is received/

### Functions

```go
func NewRelay(validator Validator, opts ...Option) *Relay
```
NewRelay creates a new Relay with the provided Validator and options. The



### Methods

```go
func (r *Relay) Handler(prefix string) func(w http.ResponseWriter, req *http.Request)
```
Handler returns an http.HandlerFunc that routes requests to the appropriate
handler based on the URL path. It expects the webhook endpoint to be at
{prefix}/webhook and the wait endpoint to be at {prefix}/wait. Requests to
other paths will receive a 404 Not Found response.


```go
func (r *Relay) ServeWebhook(w http.ResponseWriter, req *http.Request)
```
ServeWebhook handles incoming webhook requests, validates them using the
provided Validator, and relays the payload to the channel for processing.
It responds with appropriate HTTP status codes based on the validation and
processing outcome.


```go
func (r *Relay) WaitForWebhook(w http.ResponseWriter, req *http.Request)
```
WaitForWebhook waits for a payload to be received on the channel and
responds with the payload as JSON. It is intended to support long polling
by blocking until a webhook payload is available. If the request context
is cancelled while waiting, it logs the cancellation and returns without
responding.




### Type Validator
```go
type Validator func(r *http.Request) ([]byte, int)
```
Validator is called to validate and extract the webhook payload from an
incoming request. It should return the payload as a byte slice and an error
if validation fails.

### Functions

```go
func GitHubValidator(fs file.ReadFileFS, secretPaths ...string) Validator
```
GitHubValidator returns a Validator that verifies GitHub webhook
payloads using one of possibly multiple secrets stored in the provided
file.ReadFileFS instance at the provided path(s). Multiple secrets allow
for rotation since GitHub does not currently directly support rotation
the only way to change the secret used by GitHub is to create a new one,
wait for it be picked up by the validator (allowing for any caching in the
file.ReadFileFS implementation to expire), then change the secret used by
GitHub to the new one and remove the old secret from the file.ReadFileFS.
Ideally, the file.ReadFileFS instannce should be an in-memory or caching
implementation to avoid the overhead of reading the secret from disk on
every request but that also allows for the secret to be refreshed.







