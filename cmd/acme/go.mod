module cloudeng.io/webapp/cmd/acme

go 1.26

require (
	cloudeng.io/aws v0.0.0-20260225012014-415f78789833
	cloudeng.io/cmdutil v0.0.0-20260225012014-415f78789833
	cloudeng.io/errors v0.0.14-0.20260118175335-f191a42253cc
	cloudeng.io/file v0.0.0-20260225012014-415f78789833
	cloudeng.io/logging v0.0.0-20260303213431-bb1cfd0f49cd
	cloudeng.io/net v0.0.0-20260225012014-415f78789833
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	golang.org/x/crypto v0.48.0
)

require (
	cloudeng.io/algo v0.0.0-20260303213431-bb1cfd0f49cd // indirect
	cloudeng.io/os v0.0.0-20260303213431-bb1cfd0f49cd // indirect
	cloudeng.io/sync v0.0.9-0.20260114020737-744f6c0f8e64 // indirect
	cloudeng.io/sys v0.0.0-20260303213431-bb1cfd0f49cd // indirect
	cloudeng.io/text v0.0.15 // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.2 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.7 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
