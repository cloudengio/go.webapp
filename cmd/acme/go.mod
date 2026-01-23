module cloudeng.io/webapp/cmd/acme

go 1.25.5

require (
	cloudeng.io/aws v0.0.0-20260122210631-cc9df8b8152d
	cloudeng.io/cmdutil v0.0.0-20260122210631-cc9df8b8152d
	cloudeng.io/errors v0.0.14-0.20260118175335-f191a42253cc
	cloudeng.io/file v0.0.0-20260122210631-cc9df8b8152d
	cloudeng.io/logging v0.0.0-20260122210631-cc9df8b8152d
	cloudeng.io/net v0.0.0-20260122210631-cc9df8b8152d
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	golang.org/x/crypto v0.47.0
)

require (
	cloudeng.io/algo v0.0.0-20260122210631-cc9df8b8152d // indirect
	cloudeng.io/os v0.0.0-20260122210631-cc9df8b8152d // indirect
	cloudeng.io/sync v0.0.9-0.20260114020737-744f6c0f8e64 // indirect
	cloudeng.io/sys v0.0.0-20260122210631-cc9df8b8152d // indirect
	cloudeng.io/text v0.0.14 // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.7 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
