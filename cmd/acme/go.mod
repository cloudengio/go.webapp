module cloudeng.io/webapp/cmd/acme

go 1.26.4

require (
	cloudeng.io/aws v0.0.0-20260721220803-df82f2a7c54c
	cloudeng.io/cmdutil v0.0.0-20260721222700-155e56185eeb
	cloudeng.io/errors v0.0.14-0.20260312171538-61fcde6ce278
	cloudeng.io/file v0.0.0-20260721222700-155e56185eeb
	cloudeng.io/logging v0.0.0-20260721222700-155e56185eeb
	cloudeng.io/net v0.0.0-20260721222700-155e56185eeb
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	golang.org/x/crypto v0.54.0
)

require (
	cloudeng.io/algo v0.0.0-20260721222700-155e56185eeb // indirect
	cloudeng.io/os v0.0.0-20260721222700-155e56185eeb // indirect
	cloudeng.io/sync v0.0.11 // indirect
	cloudeng.io/sys v0.0.0-20260721222700-155e56185eeb // indirect
	cloudeng.io/text v0.0.16-0.20260624171915-da98fe9dec2b // indirect
	github.com/aws/aws-sdk-go-v2 v1.43.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.31 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.30 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.32 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.31 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.0 // indirect
	github.com/aws/smithy-go v1.27.4 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
