module cloudeng.io/webapp/cmd/acme

go 1.27.0

require (
	cloudeng.io/aws v0.0.0-20260902201442-bb723e109d00
	cloudeng.io/cmdutil v0.0.0-20260902173116-c569651359a0
	cloudeng.io/errors v0.0.14-0.20260312171538-61fcde6ce278
	cloudeng.io/file v0.0.0-20260902201442-bb723e109d00
	cloudeng.io/logging v0.0.0-20260902201442-bb723e109d00
	cloudeng.io/net v0.0.0-20260902173116-c569651359a0
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	golang.org/x/crypto v0.56.0
)

require (
	cloudeng.io/algo v0.0.0-20260902201442-bb723e109d00 // indirect
	cloudeng.io/os v0.0.0-20260902173116-c569651359a0 // indirect
	cloudeng.io/sync v0.0.12-0.20260804222138-e9281ed260ba // indirect
	cloudeng.io/sys v0.0.0-20260902201442-bb723e109d00 // indirect
	cloudeng.io/text v0.0.16-0.20260624171915-da98fe9dec2b // indirect
	github.com/aws/aws-sdk-go-v2 v1.45.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.33.2 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.47.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.41.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.48.0 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
